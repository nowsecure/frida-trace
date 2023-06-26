import frida from 'frida';
import fs from 'fs';
import path from 'path';
import util from 'util';

const readFile = util.promisify(fs.readFile);

export default class Application {
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

  async run(target) {
    const device = await frida.getDevice(target.device);
    this._device = device;

    const onOutput = this._onOutput.bind(this);
    device.output.connect(onOutput);

    try {
      const spawn = target.hasOwnProperty('argv');

      let pid;
      if (spawn)
        pid = await device.spawn(target.argv);
      else
        pid = target.pid;
      this._pid = pid;

      const session = await device.attach(pid);
      this._session = session;

      const agentCode = await import('./_agent');
      const agent = await readFile(agentCode, 'utf8');
      const script = await session.createScript(agent);
      this._script = script;

      const onMessage = this._onMessage.bind(this);
      script.message.connect(onMessage);

      try {
        await script.load();

        if (spawn)
          await device.resume(pid);

        await this._waitUntilDone();
      } finally {
        script.message.disconnect(onMessage);
      }
    } finally {
      device.output.disconnect(onOutput);
    }
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
      default:
        console.error(JSON.stringify(message, null, 2));
        break;
      }
    } else {
      console.error(JSON.stringify(message, null, 2));
    }
  }
}
