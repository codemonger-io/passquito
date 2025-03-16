/**
 * Makes a serializer that validates the value.
 *
 * @remarks
 *
 * The serializer can be specified to the options of `useStorage`.
 *
 * @beta
 */
export function makeValidatingSerializer<T>(
  validate: (value: unknown) => value is T
) {
  return {
    read: (raw: string) => {
      const value = JSON.parse(raw);
      if (!validate(value)) {
        throw new Error('invalid value');
      }
      return value;
    },
    write: (value: T) => JSON.stringify(value),
  };
}
