/**
 * Minimal Server-Sent Events reader for provider streams.
 *
 * Yields the `data` payload of each event (multi-line data joined with "\n").
 * Comment lines and the other fields are skipped: chat-completions streams
 * carry everything in `data`. Bytes are decoded incrementally so a multi-byte
 * character split across two chunks survives, and a final event that arrives
 * without its trailing blank line is still delivered at end of stream.
 */
export async function* parseSse(source: AsyncIterable<Uint8Array | string>): AsyncGenerator<string> {
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let dataLines: string[] = [];
  const ready: string[] = [];

  const takeLine = (rawLine: string): void => {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line === "") {
      if (dataLines.length > 0) {
        const data = dataLines.join("\n");
        dataLines = [];
        // An empty data buffer is not dispatched: `data:` alone is a keepalive.
        if (data !== "") ready.push(data);
      }
      return;
    }
    if (line.startsWith(":")) return;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    if (field !== "data") return;
    const value = colon === -1 ? "" : line.slice(colon + 1);
    dataLines.push(value.startsWith(" ") ? value.slice(1) : value);
  };

  for await (const chunk of source) {
    buffer += typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    let newline: number;
    while ((newline = buffer.indexOf("\n")) !== -1) {
      takeLine(buffer.slice(0, newline));
      buffer = buffer.slice(newline + 1);
    }
    while (ready.length > 0) yield ready.shift() as string;
  }

  buffer += decoder.decode();
  if (buffer !== "") takeLine(buffer);
  takeLine("");
  while (ready.length > 0) yield ready.shift() as string;
}

/**
 * Pass a stream through, failing if no chunk arrives within `idleMs`. A model
 * may legitimately take minutes to finish, so the bound is per gap rather than
 * per response; a source that goes silent for this long is treated as gone
 * and destroyed so the socket is released.
 */
export async function* withIdleTimeout<T>(
  source: AsyncIterable<T> & { destroy?: (error?: Error) => void },
  idleMs: number,
): AsyncGenerator<T> {
  const iterator = source[Symbol.asyncIterator]();
  try {
    for (;;) {
      let timer: NodeJS.Timeout | undefined;
      const stalled = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const gap = idleMs >= 1000 ? `${Math.round(idleMs / 1000)}s` : `${idleMs}ms`;
          const error = new Error(`no data received for ${gap}`);
          source.destroy?.(error);
          reject(error);
        }, idleMs);
      });
      let next: IteratorResult<T>;
      try {
        next = await Promise.race([iterator.next(), stalled]);
      } finally {
        clearTimeout(timer);
      }
      if (next.done) return;
      yield next.value;
    }
  } finally {
    // Reached on a consumer that stops early as well as on failure; for a
    // Readable this destroys the stream and frees its socket.
    await iterator.return?.();
  }
}
