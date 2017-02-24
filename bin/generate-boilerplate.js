#!/usr/bin/env node
'use strict';

const concat = require('concat-stream');

const input = process.stdin;
input.setEncoding('utf-8');
input.pipe(concat(writeCode));
input.resume();

const output = process.stdout;

function writeCode(data) {
  const api = JSON.parse(data);
  const code = apiDescriptionToCode(api);
  process.stdout.write(code);
}

function apiDescriptionToCode(api) {
  const funcDecls = Object.keys(api).map(name => {
    const funcDesc = api[name];
    return funcDescriptionToCode({
      name: name,
      retType: funcDesc[0],
      args: funcDesc[1]
    });
  });

  return `trace({
  module: 'libfoo.dylib',
  functions: [
    ${funcDecls.join(',\n    ')}
  ],
  callbacks: {
    onEvent(event) {
      console.log('onEvent! ' + JSON.stringify(event, null, 2));
    },
    onError(e) {
      console.error(e);
    }
  }
});

function isZero(value) {
  return value === 0;
}
`;
}

function funcDescriptionToCode(func) {
  let argDecls;
  if (func.args.length > 0) {
    argDecls = `[
      ${func.args.map(argDescriptionToCode, func).join(',\n      ')}
    ]`;
  } else {
    argDecls = '[]';
  }
  return `func('${func.name}', ${retTypeDescriptionToCode(func.retType)}, ${argDecls})`;
}

function argDescriptionToCode(arg) {
  const name = arg[0];
  const type = arg[1];
  const direction = argDirection(arg);

  let condition;
  if (direction === 'Out' && this.retType === 'Int')
    condition = `, when('result', isZero)`;
  else
    condition = '';

  return `arg${direction}('${name}', ${typeDescriptionToCode(type)}${condition})`;
}

function retTypeDescriptionToCode(type) {
  if (type === 'Void') {
    return 'null';
  }

  return `retval(${typeDescriptionToCode(type)})`;
}

function typeDescriptionToCode(type) {
  if (typeof type === 'object') {
    if (type.length === 2) {
      const pointee = type[1];
      if (pointee[0] === 'Char_S')
        return 'UTF8';
    } else if (type.length > 2) {
      if (isPointer(type[1]))
        return 'pointer(POINTER)';
    }
    return 'POINTER';
  } else if (type === 'UChar') {
    return 'BYTE';
  } else {
    return type.toUpperCase();
  }
}

function argDirection(arg) {
  const type = arg[1];
  if (typeof type === 'object' && type.length > 2) {
    if (isPointer(type[1]))
      return 'Out';
    else
      return 'In';
  } else {
    return 'In';
  }
}

function isPointer(type) {
  return type[0] === 'Pointer';
}
