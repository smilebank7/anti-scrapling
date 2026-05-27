import type { SpeechProbe } from '../types';

const VOICE_TIMEOUT_MS = 500;

export async function collectSpeech(): Promise<SpeechProbe> {
  if (!window.speechSynthesis) {
    return { voices_count: 0, voices: [] };
  }

  const voices = await waitForVoices(window.speechSynthesis);
  return {
    voices_count: voices.length,
    voices: voices.map(formatVoice).sort()
  };
}

function waitForVoices(synth: SpeechSynthesis): Promise<SpeechSynthesisVoice[]> {
  const initial = synth.getVoices();
  if (initial.length > 0) {
    return Promise.resolve(initial);
  }

  return new Promise((resolve) => {
    const finish = () => {
      synth.removeEventListener('voiceschanged', finish);
      resolve(synth.getVoices());
    };

    synth.addEventListener('voiceschanged', finish, { once: true });
    setTimeout(finish, VOICE_TIMEOUT_MS);
  });
}

function formatVoice(voice: SpeechSynthesisVoice): string {
  return `${voice.name}|${voice.lang}|${voice.voiceURI}|${voice.localService ? 'local' : 'remote'}`;
}
