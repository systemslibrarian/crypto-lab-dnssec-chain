/**
 * Element helpers.
 *
 * Small on purpose: every panel builds real DOM, and the accessibility rules
 * this lab is gated on — an accessible name on every control, `role="list"`
 * paired with `role="listitem"`, live regions on anything that changes after a
 * click — are easier to get right when the construction is explicit than when
 * it is hidden behind a template string.
 */

export type Attrs = Record<string, string | number | boolean | undefined>;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string | null | undefined)[] = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (name === 'class') node.className = String(value);
    else if (name === 'text') node.textContent = String(value);
    else if (value === true) node.setAttribute(name, '');
    else node.setAttribute(name, String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function replace(node: Element, ...children: (Node | string)[]): void {
  clear(node);
  for (const child of children) node.append(child);
}

/**
 * State is never carried by colour alone (WCAG 1.4.1): every one of these
 * pairs a glyph, a word, and a colour, and the glyph is `aria-hidden` because
 * the word beside it already says the same thing to a screen reader.
 */
export type Tone = 'ok' | 'bad' | 'warn' | 'info' | 'muted';

const GLYPH: Record<Tone, string> = {
  ok: '✓',
  bad: '✗',
  warn: '⚠',
  info: '●',
  muted: '○',
};

export function badge(tone: Tone, word: string, detail?: string): HTMLElement {
  return el('span', { class: `badge badge-${tone}` }, [
    el('span', { class: 'badge-glyph', 'aria-hidden': 'true', text: GLYPH[tone] }),
    el('span', { class: 'badge-word', text: word }),
    detail ? el('span', { class: 'badge-detail', text: detail }) : null,
  ]);
}

/** A checklist row: glyph + label + the concrete detail that was compared. */
export function checkRow(passed: boolean, label: string, detail: string): HTMLElement {
  return el('li', { class: `check check-${passed ? 'ok' : 'bad'}`, role: 'listitem' }, [
    el('span', { class: 'check-glyph', 'aria-hidden': 'true', text: passed ? GLYPH.ok : GLYPH.bad }),
    el('div', { class: 'check-body' }, [
      el('span', { class: 'check-label', text: label }),
      el('span', { class: 'check-detail', text: detail }),
      el('span', { class: 'visually-hidden', text: passed ? ' — passed' : ' — failed' }),
    ]),
  ]);
}

/**
 * A `role="list"` that refuses to be empty.
 *
 * An explicit `role="list"` on an element with no children fails axe's
 * `aria-required-children` — and that finding lands in the `incomplete`
 * bucket, not in `violations`, so a gate that reads only violations never sees
 * it. Every list on this page is built through here, so the empty state
 * degrades to a sentence rather than to an invalid landmark.
 */
export function list(
  tag: 'ul' | 'ol',
  className: string,
  label: string,
  rows: readonly HTMLElement[],
  emptyText: string
): HTMLElement {
  if (rows.length === 0) return el('p', { class: 'prose', text: emptyText });
  return el(tag, { class: className, role: 'list', 'aria-label': label }, [...rows]);
}

export function checkList(rows: HTMLElement[], label: string, emptyText = 'Nothing to check yet.'): HTMLElement {
  return list('ul', 'check-list', label, rows, emptyText);
}

export function button(label: string, onClick: () => void, attrs: Attrs = {}): HTMLButtonElement {
  const node = el('button', { type: 'button', class: 'btn', ...attrs }, [label]);
  node.addEventListener('click', onClick);
  return node;
}

/**
 * A live region for anything that appears after an action.
 *
 * `role="status"` with `aria-live="polite"` is what makes a verdict that
 * replaces itself audible to a screen-reader user who never sees it appear.
 */
export function liveRegion(label: string, id?: string): HTMLElement {
  return el('div', {
    class: 'live',
    id,
    role: 'status',
    'aria-live': 'polite',
    'aria-label': label,
  });
}

/**
 * A scrollable region, wired for the keyboard.
 *
 * An `overflow: auto` box with no focusable content inside is unreachable
 * without a pointer, so it needs `tabindex="0"`, a role, and a name (WCAG
 * 2.1.1). This is the single rule the CI gate catches most often.
 */
export function scroller(label: string, ...children: Node[]): HTMLElement {
  return el(
    'div',
    { class: 'scroller', tabindex: '0', role: 'group', 'aria-label': label },
    children
  );
}

/** A disclosure that ships SHUT, which is the state most readers arrive at. */
export function disclosure(summary: string, ...children: Node[]): HTMLDetailsElement {
  return el('details', { class: 'disclose' }, [
    el('summary', { class: 'disclose-summary' }, [summary]),
    el('div', { class: 'disclose-body' }, children),
  ]) as HTMLDetailsElement;
}

export function para(text: string, cls = 'prose'): HTMLElement {
  return el('p', { class: cls, text });
}

/** A labelled control group; the label is what gives the group its name. */
export function controlGroup(label: string, ...controls: Node[]): HTMLElement {
  return el('div', { class: 'control-group', role: 'group', 'aria-label': label }, [
    el('span', { class: 'control-group-label', text: label }),
    el('div', { class: 'control-group-body' }, controls),
  ]);
}
