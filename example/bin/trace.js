#!/usr/bin/env node
const Application = require('../lib/application');
const chalk = require('chalk');
const hexy = require('hexy').hexy;

class ConsoleUI {
  onEvents(events) {
    events.forEach(event => {
      const args = event.args;
      const argNames = Object.keys(args);

      const heading = event.name + '(' + argNames.reduce((result, name) => {
        const value = args[name];
        if (!(value instanceof Buffer))
          result.push(name + '=' + annotate(value));
        return result;
      }, []).join(', ') + ') => ' + event.result;

      const sections = argNames.reduce((result, name) => {
        const value = args[name];
        if (value instanceof Buffer) {
          result.push('\n' + name + ':\n' + hexy(value, { format: 'twos' }));
        }
        return result;
      }, []).join('\n');

      console.log(chalk.green(heading) + '\n' + sections);
    });
  }

  onOutput(pid, fd, data) {
    let text = data.toString();
    if (text[text.length - 1] === '\n')
      text = text.substr(0, text.length - 1);
    const lines = text.split('\n');
    const prefix = ((fd === 1) ? chalk.bold('stdout>') : chalk.red('stderr>')) + ' ';
    console.log(prefix + lines.join('\n' + prefix) + '\n');
  }

  onError(error) {
    console.error(error);
    process.exitCode = 1;
  }
}

function annotate(value) {
  if (typeof value === 'string')
    return '"' + value + '"';
  else
    return value;
}

function usage() {
  console.error('Usage: ' + process.argv[0] + ' <device-id> launch|attach args...');
  process.exit(1);
}

if (process.argv.length < 5)
  usage();

const device = process.argv[2];
const action = process.argv[3];
let target;
if (action === 'launch') {
  target = {
    device: device,
    argv: process.argv.slice(4)
  };
} else if (action === 'attach') {
  target = {
    device: device,
    pid: parseInt(process.argv[4], 10)
  };
} else {
  usage();
}

const ui = new ConsoleUI();
const application = new Application(ui);
application.run(target).catch(ui.onError.bind(ui));
