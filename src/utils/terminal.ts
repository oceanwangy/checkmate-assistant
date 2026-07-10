export function safeTerminalText(value: string): string {
  return [...value]
    .filter((character) => {
      const code = character.charCodeAt(0);
      return (
        character === "\n" ||
        character === "\t" ||
        (code >= 32 && (code < 127 || code > 159))
      );
    })
    .join("");
}
