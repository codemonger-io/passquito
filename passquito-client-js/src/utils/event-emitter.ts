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
   * Emits a given event.
   *
   * @beta
   */
  emit(event: T): void {
    try {
      const listeners = [...this.listeners];
      for (const listener of listeners) {
        listener(event);
      }
    } catch (_) {}
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
