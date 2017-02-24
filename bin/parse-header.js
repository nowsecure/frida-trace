#!/usr/bin/env node
'use strict';

const clang = require('frida-libclang');
const dynamicClang = require('frida-libclang/lib/dynamic_clang');

const clangApi = dynamicClang.libclang;
const {CXCallingConv_Invalid} = dynamicClang.CONSTANTS.CXCallingConv;

const Cursor = clang.Cursor;
const Index = clang.Index;
const TranslationUnit = clang.TranslationUnit;
const Type = clang.Type;

if (process.argv.length !== 3) {
  process.stderr.write('Usage: ' + process.argv[1] + ' /path/to/header.h\n');
  process.exit(1);
}

const data = parseHeader(process.argv[2]);
process.stdout.write(JSON.stringify(data));

function parseHeader (path) {
  const index = new Index(true, true);
  const unit = TranslationUnit.fromSource(index, path, ['-I/usr/include']);

  const funcs = [];
  const structs = [];

  unit.cursor.visitChildren(function (parent) {
    switch (this.kind) {
      case Cursor.FunctionDecl:
        funcs.push(parseFunction(this));
        break;
      case Cursor.StructDecl: {
        const struct = parseStruct(this);
        const [name, funcs] = struct;
        if (name !== null && funcs.length > 0) {
          structs.push(struct);
        }
        break;
      }
    }
    return Cursor.Continue;
  });

  index.dispose();

  return {
    functions: funcs,
    structs: structs
  };
}

function parseFunction (cursor) {
  const name = cursor.spelling;

  const retType = parseType(new Type(clangApi.clang_getCursorResultType(cursor._instance)));
  const args = [];

  cursor.visitChildren(function (parent) {
    switch (this.kind) {
      case Cursor.ParmDecl:
        const argName = this.spelling || 'a' + (args.length + 1);
        const argType = parseType(this.type);
        args.push([argName, argType]);
        break;
      default:
        break;
    }
  });

  return [name, retType, args];
}

function parseStruct (cursor) {
  const name = cursor.spelling;
  if (name === '') {
    return [null, []];
  }

  const funcs = [];

  let func = null;
  let args = null;

  cursor.visitChildren(function (parent) {
    switch (this.kind) {
      case Cursor.FieldDecl:
        if (isFunctionPointer(this.type)) {
          const offset = clangApi.clang_Cursor_getOffsetOfField(this._instance) / 8 / 8;

          args = [];
          func = [offset, this.spelling, 'Void', args];

          funcs.push(func);

          return Cursor.Recurse;
        }
        break;
      case Cursor.TypeRef:
        func[2] = parseType(this);
        break;
      case Cursor.ParmDecl:
        const argName = this.spelling || 'a' + (args.length + 1);
        const argType = parseType(this.type);
        args.push([argName, argType]);
        break;
      default:
        break;
    }

    return Cursor.Continue;
  });

  return [name, funcs];
}

function isFunctionPointer (type) {
  const name = type.spelling;
  if (name !== 'Pointer') {
    return false;
  }

  const conv = clangApi.clang_getFunctionTypeCallingConv(clangApi.clang_getPointeeType(type._instance));

  return conv !== CXCallingConv_Invalid;
}

function parseType (type) {
  const name = type.spelling;
  if (name === 'Pointer') {
    const path = [
      ['Pointer', parseQualifiers(type)]
    ];

    let t = type;
    do {
      t = new Type(clangApi.clang_getPointeeType(t._instance));
      path.push([t.spelling, parseQualifiers(t)]);
    } while (t.spelling === 'Pointer');

    return path;
  } else if (name === 'Typedef') {
    return parseType(new Type(clangApi.clang_getCanonicalType(type._instance)));
  } else {
    return name;
  }
}

function parseQualifiers (type) {
  return clangApi.clang_isConstQualifiedType(type._instance) ? ['const'] : [];
}
