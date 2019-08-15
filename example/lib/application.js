const co = require('co');
const frida = require('frida');
const fs = require('fs');
const path = require('path');

class Application {
  constructor(ui) {
    this.ui = ui;

    this._device = null;
    this._pid = 0;
    this._session = null;
    this._script = null;
    this._done = new Promise((resolve) => {
      this._onDone = resolve;
    });
  }

  run(target) {
    return co(function* () {
      const device = yield frida.getDevice(target.device);
      this._device = device;

      const onOutput = this._onOutput.bind(this);
      device.events.listen('output', onOutput);

      try {
        const spawn = target.hasOwnProperty('argv');

        let pid;
        if (spawn)
          pid = yield device.spawn(target.argv);
        else
          pid = target.pid;
        this._pid = pid;

        const session = yield device.attach(pid);
        this._session = session;

        const agent = yield readFile(require.resolve('./_agent'), 'utf8');
        const script = yield session.createScript(agent);
        this._script = script;

        const onMessage = this._onMessage.bind(this);
        script.events.listen('message', onMessage);

        try {
          yield script.load();

          const api = yield script.getExports();

          if (spawn)
            yield device.resume(pid);

          yield this._waitUntilDone();
        } finally {
          script.events.unlisten('message', onMessage);
        }
      } finally {
        device.events.unlisten('output', onOutput);
      }
    }.bind(this));
  }

  _waitUntilDone() {
    return this._done;
  }

  _onOutput(pid, fd, data) {
    this.ui.onOutput(pid, fd, data);
  }

  _onMessage(message, data) {
    if (message.type === 'send') {
      const stanza = message.payload;
      switch (stanza.name) {
      case '+events': {
        const payload = stanza.payload;
        const items = payload.items;
        const mappings = payload.mappings;
        mappings.forEach(mapping => {
          const index = mapping[0];
          const argName = mapping[1];
          const offset = mapping[2];
          const length = mapping[3];
          items[index].args[argName] = Buffer.from(data, offset, length);
        });
        this.ui.onEvents(items);
        break;
      }
      case '+flush':
        this._script.postMessage({ type: '+flush-ack' });
        this._onDone();
        break;
      default:
        console.error(JSON.stringify(message, null, 2));
        break;
      }
    } else {
      console.error(JSON.stringify(message, null, 2));
    }
  }
}

function readFile(file, options) {
  return new Promise(function (resolve, reject) {
    fs.readFile(file, options, (err, data) => {
      if (!err)
        resolve(data);
      else
        reject(err);
    });
  });
}

module.exports = Application;
