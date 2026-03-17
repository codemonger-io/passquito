/**
 * Event listener.
 *
 * @beta
 */
export type EventListener<T> = (event: T) => void;

/**
 * Simple event emitter.
 *
 * @beta
 */
export class EventEmitter<T> {
  private listeners: EventListener<T>[];

  constructor() {
    this.listeners = [];
  }

  /**
   * Emits a given emit.
   *
   * @beta
   */
  emit(event: T): void {
    for (const listener of this.listeners) {
      listener(event);
    }
  }

  /**
   * Adds a listener.
   *
   * @beta
   */
  addListener(listener: EventListener<T>): void {
    this.listeners.push(listener);
  }
}
