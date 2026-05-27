import type { RuntimeProbe } from '../types';

const PLAYWRIGHT_RE = /__playwright|__pwInitScripts|patchright/i;

export function collectRuntime(): RuntimeProbe {
  const functionToString = Function.prototype.toString.toString();
  const consoleDebug = console.debug;
  const stack = testStack();

  return {
    function_to_string_native: functionToString.includes('[native code]'),
    console_debug_arity: consoleDebug.length,
    console_debug_to_string: String(consoleDebug),
    eval_length: eval.length,
    error_stack_contains_pw_sig: PLAYWRIGHT_RE.test(stack)
  };
}

function testStack(): string {
  try {
    throw new Error('__as_runtime_probe__');
  } catch (error) {
    return error instanceof Error ? error.stack || '' : String(error);
  }
}
