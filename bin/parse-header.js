#!/usr/bin/env node
'use strict';

const clang = require('libclang');
const clangApi = require('libclang/lib/dynamic_clang').libclang;

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

function parseHeader(path) {
  const index = new Index(true, true);
  const unit = TranslationUnit.fromSource(index, path, ['-I/usr/include']);

  const result = {};
  let func = null;
  let args = null;
  unit.cursor.visitChildren(function (parent) {
    switch (this.kind) {
      case Cursor.FunctionDecl:
        const retType = parseType(new Type(clangApi.clang_getCursorResultType(this._instance)));
        args = [];
        func = [retType, args];
        result[this.spelling] = func;
        return Cursor.Recurse;
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

  index.dispose();

  return result;
}

function parseType(type) {
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

function parseQualifiers(type) {
  return clangApi.clang_isConstQualifiedType(type._instance) ? ['const'] : [];
}
