const IN = Symbol('in');
const OUT = Symbol('out');
const IN_OUT = Symbol('in-out');

const pointerSize = Process.pointerSize;

module.exports = trace;

function trace (spec) {
  const {module, vtable, functions} = spec;
  const {onError} = spec.callbacks;

  const listeners = [];
  const intercept = makeInterceptor(spec);

  if (module !== undefined) {
    functions.forEach(func => {
      const {name} = func;

      const impl = Module.findExportByName(module, name);
      if (impl === null) {
        onError(new Error(`Failed to resolve ${module}!${name}`));
        return;
      }

      listeners.push(intercept(func, impl));
    });
  } else if (vtable !== undefined) {
    let offset = 0;

    for (let entry of functions) {
      const isPadding = Array.isArray(entry);
      if (isPadding) {
        const [n] = entry;
        offset += n * pointerSize;
        continue;
      }

      let impl;
      try {
        impl = vtable.add(offset).readPointer();
      } catch (e) {
        onError(new Error(`Failed to read from vtable at offset ${offset}: ${e}`));
        break;
      }

      listeners.push(intercept(entry, impl));

      offset += pointerSize;
    }
  } else {
    throw new Error('Either a module or a vtable must be specified');
  }
  
  return new Session(listeners);
}

trace.func = func;
trace.argIn = argIn;
trace.argOut = argOut;
trace.argInOut = argInOut;
trace.retval = retval;
trace.padding = padding;

trace.bind = bind;
trace.when = when;

trace.types = {
  BOOL: bool(),
  BYTE: byte(),
  SHORT: short(),
  INT: int(),
  POINTER: pointer(),
  BYTE_ARRAY: byteArray(),
  UTF8: utf8(),
  UTF16: utf16(),
  CSTRING: cstring(),

  bool: bool,
  byte: byte,
  short: short,
  int: int,
  pointer: pointer,
  byteArray: byteArray,
  utf8: utf8,
  utf16: utf16,
  cstring: cstring
};

function makeInterceptor (spec) {
  const {onEvent, onEnter, onLeave, onError} = spec.callbacks;

  return function (func, impl) {
    const name = func.name;

    const inputActions = [];
    const outputActions = [];
    if (!computeActions(func, inputActions, outputActions)) {
      onError(new Error(`Oops. It seems ${module}!${name} has circular dependencies.`));
      return;
    }

    const numArgs = func.args.length;
    const numInputActions = inputActions.length;
    const numOutputActions = outputActions.length;

    return Interceptor.attach(impl, {
      onEnter (args) {
        const values = [];
        for (let i = 0; i !== numArgs; i++) {
          values.push(args[i]);
        }

        const event = new Event(name);
        for (let i = 0; i !== numInputActions; i++) {
          const [action, params] = inputActions[i];
          action(values, event, params);
        }
        if (onEnter !== undefined) {
          onEnter.call(this, event, args);
        }

        this.values = values;
        this.event = event;
      },
      onLeave (retval) {
        const values = this.values;
        const event = this.event;

        values.push(retval);

        for (let i = 0; i !== numOutputActions; i++) {
          const [action, params] = outputActions[i];
          action(values, event, params);
        }
        if (onLeave !== undefined) {
          onLeave.call(this, event, retval);
        }

        onEvent(event);
      }
    });
  };
}

function computeActions (func, inputActions, outputActions) {
  const args = func.args.slice();
  if (func.ret !== null) {
    args.push(func.ret);
  }

  const satisfied = new Set();
  let previousSatisfiedSize;

  do {
    previousSatisfiedSize = satisfied.size;

    args.forEach(function (arg, index) {
      if (satisfied.has(arg.name)) {
        return;
      }
      const remaining = arg.requires.filter(dep => !satisfied.has(dep));
      if (remaining.length === 0) {
        inputActions.push(computeAction(arg, index));
        satisfied.add(arg.name);
      }
    });
  } while (satisfied.size !== previousSatisfiedSize);

  satisfied.add('$out');

  do {
    previousSatisfiedSize = satisfied.size;

    args.forEach(function (arg, index) {
      if (satisfied.has(arg.name)) {
        return;
      }
      const remaining = arg.requires.filter(dep => !satisfied.has(dep));
      if (remaining.length === 0) {
        outputActions.push(computeAction(arg, index));
        satisfied.add(arg.name);
      }
    });
  } while (satisfied.size !== previousSatisfiedSize);

  return !args.some(arg => !satisfied.has(arg.name));
}

function computeAction (arg, index) {
  const {name, type, condition} = arg;

  const hasDependentType = Array.isArray(type);
  const hasCondition = condition !== null;

  if (hasDependentType) {
    if (hasCondition) {
      return [readValueWithDependentTypeConditionally, [index, name, type[0].parse, type[1], condition]];
    }
    return [readValueWithDependentType, [index, name, type[0].parse, type[1]]];
  }
  if (hasCondition) {
    return [readValueConditionally, [index, name, type.parse, condition]];
  }
  return [readValue, [index, name, type.parse]];
}

function readValue (values, event, params) {
  const [index, name, parse] = params;

  event.set(name, parse(values[index]));
}

function readValueConditionally (values, event, params) {
  const [index, name, parse, condition] = params;

  if (condition.predicate(event.get(condition.value))) {
    event.set(name, parse(values[index]));
  }
}

function readValueWithDependentType (values, event, params) {
  const [index, name, parse, binding] = params;

  const typeParameters = {};
  typeParameters[binding.property] = event.get(binding.value);
  event.set(name, parse(values[index], typeParameters));
}

function readValueWithDependentTypeConditionally (values, event, params) {
  const [index, name, parse, binding, condition] = params;

  if (condition.predicate(event.get(condition.value))) {
    const typeParameters = {};
    typeParameters[binding.property] = event.get(binding.value);
    event.set(name, parse(values[index], typeParameters));
  }
}

function func (name, ret, args) {
  return {
    name: name,
    ret: ret,
    args: args
  };
}

function argIn (name, type, condition) {
  return arg(IN, name, type, condition);
}

function argOut (name, type, condition) {
  return arg(OUT, name, type, condition);
}

function argInOut (name, type, condition) {
  return arg(IN_OUT, name, type, condition);
}

function arg (direction, name, type, condition) {
  condition = condition || null;

  return {
    direction: direction,
    name: name,
    type: type,
    condition: condition,
    requires: dependencies(direction, type, condition)
  };
}

function retval (type, condition) {
  return argOut('result', type, condition);
}

function padding (n) {
  return [n];
}

function bind (property, value) {
  return {
    property: property,
    value: value
  };
}

function when (value, predicate) {
  return {
    value: value,
    predicate: predicate
  };
}

function dependencies (direction, type, condition) {
  const result = [];

  if (direction === OUT) {
    result.push('$out');
  }

  if (Array.isArray(type)) {
    result.push(type[1].value);
  }

  if (condition !== null) {
    result.push(condition.value);
  }

  return result;
}

function bool () {
  return {
    parse (rawValue) {
      return !!rawValue.toInt32();
    },
    read (ptr) {
      return !!ptr.readU8();
    }
  };
}

function byte () {
  return {
    parse (rawValue) {
      return rawValue.toInt32() & 0xff;
    },
    read (ptr) {
      return ptr.readU8();
    }
  };
}

function short () {
  return {
    parse (rawValue) {
      return rawValue.toInt32() & 0xffff;
    },
    read (ptr) {
      return ptr.readShort();
    }
  };
}

function int () {
  return {
    parse (rawValue) {
      return rawValue.toInt32();
    },
    read (ptr) {
      return ptr.readInt();
    }
  };
}

function pointer (pointee) {
  return {
    parse (rawValue, parameters) {
      if (pointee) {
        if (rawValue.isNull()) {
          return null;
        } else {
          return pointee.read(rawValue, parameters);
        }
      } else {
        return rawValue;
      }
    },
    read (ptr) {
      return ptr.readPointer();
    }
  };
}

function byteArray () {
  return pointer({
    read (ptr, parameters) {
      return ptr.readByteArray(parameters.length);
    }
  });
}

function utf8 () {
  return pointer({
    read (ptr, parameters) {
      const length = (parameters === undefined) ? -1 : parameters.length;
      return ptr.readUtf8String(length);
    }
  });
}

function utf16 () {
  return pointer({
    read (ptr, parameters) {
      const length = (parameters === undefined) ? -1 : parameters.length;
      return ptr.readUtf16String(length);
    }
  });
}

function cstring () {
  return pointer({
    read (ptr, parameters) {
      const length = (parameters === undefined) ? -1 : parameters.length;
      return ptr.readCString(length);
    }
  });
}

class Event {
  constructor (name) {
    this.name = name;
    this.args = {};
  }

  get (key) {
    return (key === 'result') ? this.result : this.args[key];
  }

  set (key, value) {
    if (key === 'result') {
      this.result = value;
    } else {
      this.args[key] = value;
    }
  }
}

class Session {
  constructor (listeners) {
    this._listeners = listeners;
  }

  stop () {
    this._listeners.forEach(listener => {
      listener.detach();
    });
  }
}
