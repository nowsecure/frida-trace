const trace = require('frida-trace');

const func = trace.func;
const argIn = trace.argIn;
const argOut = trace.argOut;
const retval = trace.retval;

const types = trace.types;
const pointer = types.pointer;
const INT = types.INT;
const POINTER = types.POINTER;
const UTF8 = types.UTF8;
const BYTE_ARRAY = types.BYTE_ARRAY;

const bind = trace.bind;
const when = trace.when;

rpc.exports = {
  dispose() {
    flushEvents();
  },
};

trace({
  module: null,
  functions: [
    func('strlen', retval(INT), [
      argIn('s', UTF8)
    ]),
    func('read', retval(INT), [
      argIn('fd', INT),
      argOut('buffer', [BYTE_ARRAY, bind('length', 'result')], when('result', isGreaterThanZero)),
      argIn('length', INT),
    ]),
  ],
  callbacks: {
    onEvent(event) {
      scheduleEvent(event);
    },
    onError(e) {
      console.error(e);
    }
  }
});

const pending = [];
let timer = null;

function scheduleEvent(event) {
  pending.push(event);
  if (timer === null) {
    timer = setTimeout(() => {
      timer = null;
      flushEvents();
    }, 500);
  }
}

function flushEvents() {
  if (timer !== null) {
    clearTimeout(timer);
    timer = null;
  }
  const events = pending.splice(0);

  const blobs = events.reduce((result, event, index) => {
    const args = event.args;
    Object.keys(args).forEach(argName => {
      const argValue = args[argName];
      if (argValue instanceof ArrayBuffer) {
        result.push([index, argName, argValue]);
      }
    });
    return result;
  }, []);

  const dataSize = blobs.reduce((total, blob) => total + blob[2].byteLength, 0);
  const data = new Uint8Array(dataSize);
  let offset = 0;
  const mappings = blobs.map(blob => {
    const chunk = new Uint8Array(blob[2]);
    data.set(chunk, offset);

    const length = chunk.length;
    const mapping = [blob[0], blob[1], offset, length];
    offset += length;

    return mapping;
  });

  send({
    name: '+events',
    payload: {
      items: events,
      mappings: mappings
    }
  }, data.buffer);
}

function isGreaterThanZero(value) {
  return value > 0;
}
