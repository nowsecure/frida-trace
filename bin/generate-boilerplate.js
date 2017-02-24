#!/usr/bin/env node
'use strict';

const concat = require('concat-stream');

const input = process.stdin;
input.setEncoding('utf-8');
input.pipe(concat(writeCode));
input.resume();

const output = process.stdout;

function writeCode (data) {
  const api = JSON.parse(data);
  const code = apiDescriptionToCode(api);
  process.stdout.write(code);
}

function apiDescriptionToCode (api) {
  const {functions, structs} = api;

  return []
    .concat(functionDescriptionsToCode(functions))
    .concat(structDescriptionsToCode(structs))
    .join('\n');
}

function functionDescriptionsToCode (funcs) {
  if (funcs.length === 0) {
    return [];
  }

  const funcDecls = funcs.map(func => {
    const [name, retType, args] = func;
    return funcDescriptionToCode({
      name: name,
      retType: retType,
      args: args
    }, 1);
  });

  const code = `trace({
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

  return [code];
}

function structDescriptionsToCode (structs) {
  if (structs.length === 0) {
    return [];
  }

  const code = structs
    .reduce((state, [name, funcs]) => {
      const body = structDescriptionToCode(funcs);

      let code;
      const {previous} = state;
      if (previous !== null && strippedName(name) === strippedName(previous.name) && body.startsWith(previous.body)) {
        code = `const ${name} = ${previous.name}.concat([
${body.substr(previous.body.length + 2)}
]);`;
      } else {
        code = `const ${name} = [
  ${body}
];`;
      }

      state.entries.push(code);
      state.previous = {
        name: name,
        body: body
      };

      return state;
    }, {
      entries: [],
      previous: null
    })
    .entries
    .join('\n\n');

  return [code];
}

function strippedName (name) {
  return name.replace(/[0-9]/g, '');
}

function structDescriptionToCode (funcs) {
  const funcDecls = funcs
    .filter(([, , retType]) => retType !== null)
    .reduce((state, [offset, name, retType, args]) => {
      const padding = offset - state.previousOffset - 1;
      if (padding > 0) {
        state.items.push(`padding(${padding})`);
      }
      state.previousOffset = offset;

      state.items.push(funcDescriptionToCode({
        offset: offset,
        name: name,
        retType: retType,
        args: args
      }, 0));

      return state;
    }, {
      items: [],
      previousOffset: 0
    })
    .items;
  return funcDecls.join(',\n  ');
}

function funcDescriptionToCode (func, indentLevel) {
  const indentation = makeIndentation(indentLevel);
  let argDecls;
  if (func.args.length > 0) {
    argDecls = `[
${indentation}    ${func.args.map(argDescriptionToCode, func).join(',\n' + indentation + '    ')}
${indentation}  ]`;
  } else {
    argDecls = '[]';
  }
  return `func('${func.name}', ${retTypeDescriptionToCode(func.retType)}, ${argDecls})`;
}

function argDescriptionToCode (arg) {
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

function retTypeDescriptionToCode (type) {
  if (type === 'Void') {
    return 'null';
  }

  return `retval(${typeDescriptionToCode(type)})`;
}

function typeDescriptionToCode (type) {
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

function argDirection (arg) {
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

function isPointer (type) {
  return type[0] === 'Pointer';
}

function makeIndentation (level) {
  const result = [];
  for (let i = 0; i !== level; i++) {
    result.push('  ');
  }
  return result.join('');
}
