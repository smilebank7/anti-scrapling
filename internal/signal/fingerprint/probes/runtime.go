package probes

import "github.com/anti-scrapling/anti-scrapling/internal/types"

// Runtime scores native integrity and Playwright runtime signatures.
func Runtime(report types.FingerprintReport) []types.Signal {
	runtime := report.Runtime
	signals := make([]types.Signal, 0, 3)

	if runtime.ConsoleDebugArity == 0 {
		signals = append(signals, newSignal(
			"runtime_console_debug_disabled",
			60,
			"console.debug.length is zero, matching the patchright Console API patch",
			map[string]any{"console_debug_arity": runtime.ConsoleDebugArity},
		))
	}

	if !runtime.FunctionToStringNative {
		signals = append(signals, newSignal(
			"runtime_to_string_proxy",
			35,
			"Function.prototype.toString failed the native reflection probe",
			map[string]any{"function_to_string_native": runtime.FunctionToStringNative},
		))
	}

	if runtime.ErrorStackContainsPwSig {
		signals = append(signals, newSignal(
			"runtime_error_stack_pw_signature",
			70,
			"error stack contains a Playwright init-script signature",
			map[string]any{"error_stack_contains_pw_sig": runtime.ErrorStackContainsPwSig},
		))
	}

	return signals
}
