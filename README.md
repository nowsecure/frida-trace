# frida-trace

Trace APIs declaratively through [Frida](http://frida.re).

## Example

```js
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

trace({
  module: 'libsqlite3.dylib',
  functions: [
    func('sqlite3_open', retval(INT), [
      argIn('filename', UTF8),
      argOut('ppDb', pointer(POINTER), when('result', isZero)),
    ]),
    func('sqlite3_prepare_v2', retval(INT), [
      argIn('db', POINTER),
      argIn('zSql', [UTF8, bind('length', 'nByte')]),
      argIn('nByte', INT),
      argOut('ppStmt', pointer(POINTER), when('result', isZero)),
    ])
  ],
  callbacks: {
    onEvent(event) {
      console.log('onEvent! ' + JSON.stringify(event, null, 2));
    },
    onEnter(event, context) {
      event.trace = Thread.backtrace(context)
        .map(DebugSymbol.fromAddress)
        .filter(x => x.name);
    },
    onError(e) {
      console.error(e);
    }
  }
});

function isZero(value) {
  return value === 0;
}
```

## Auto-generating boilerplate from header files

```sh
$ ./bin/parse-header.js /usr/include/sqlite3.h | ./bin/generate-boilerplate.js
trace({
  module: 'libfoo.dylib',
  functions: [
    func('sqlite3_libversion', retval(UTF8), []),
    func('sqlite3_sourceid', retval(UTF8), []),
    func('sqlite3_libversion_number', retval(INT), []),
    func('sqlite3_compileoption_used', retval(INT), [
      argIn('zOptName', UTF8)
    ]),
    func('sqlite3_compileoption_get', retval(UTF8), [
      argIn('N', INT)
    ]),
    func('sqlite3_threadsafe', retval(INT), []),
    func('sqlite3_close', retval(INT), [
      argIn('a1', POINTER)
    ]),
    func('sqlite3_close_v2', retval(INT), [
      argIn('a1', POINTER)
    ]),
    func('sqlite3_exec', retval(INT), [
      argIn('a1', POINTER),
      argIn('sql', UTF8),
      argIn('callback', POINTER),
      argIn('a4', POINTER),
      argOut('errmsg', pointer(POINTER), when('result', isZero))
    ]),
...
```
