/**
 * The page shell: hero, plain-language intro, honest scoping, and the tabs.
 *
 * Panels render LAZILY on first activation and are `hidden` until then, so
 * what a reader arrives at is one panel, not seven. That is also what makes
 * the accessibility gate meaningful: it has to drive the real controls to
 * reach a panel, exactly as a reader does, instead of stripping `hidden` and
 * scanning a rendering nobody ever sees.
 */

import { el, para } from './dom.ts';
import { renderChainPanel } from './panels/chain.ts';
import { renderBreakPanel } from './panels/break.ts';
import { renderInsecurePanel } from './panels/insecure.ts';
import { renderWalkPanel } from './panels/walk.ts';
import { renderNsec3Panel } from './panels/nsec3.ts';
import { renderOnlinePanel } from './panels/online.ts';
import { renderRolloverPanel } from './panels/rollover.ts';

interface TabSpec {
  readonly id: string;
  readonly label: string;
  readonly render: (host: HTMLElement) => void | Promise<void>;
}

const TABS: readonly TabSpec[] = [
  { id: 'chain', label: 'Build the chain', render: renderChainPanel },
  { id: 'break', label: 'Break each link', render: renderBreakPanel },
  { id: 'insecure', label: 'No DS: insecure', render: renderInsecurePanel },
  { id: 'walk', label: 'Walk the zone', render: renderWalkPanel },
  { id: 'nsec3', label: 'NSEC3 guessing', render: renderNsec3Panel },
  { id: 'online', label: 'Denial on demand', render: renderOnlinePanel },
  { id: 'rollover', label: 'Key rollover', render: renderRolloverPanel },
];

function hero(): HTMLElement {
  return el('div', { class: 'cl-hero' }, [
    el('div', { class: 'cl-hero-main' }, [
      el('h1', { class: 'cl-hero-title', text: 'DNSSEC Chain' }),
      el('p', { class: 'cl-hero-sub', text: 'Authenticated denial · RFC 4034 · RFC 5155' }),
      el('p', {
        class: 'cl-hero-desc',
        text:
          'Validates a real chain from the IANA root trust anchor to a signed answer, then turns NSEC’s proof that a name does not exist into a complete list of the names that do.',
      }),
    ]),
    el('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text:
          'DNS decides where your traffic goes before any certificate is checked. DNSSEC is the second trust hierarchy that answers for it — and the proofs it uses to say “no” were what let anyone read a private zone out of a public nameserver.',
      }),
    ]),
  ]);
}

function intro(): HTMLElement {
  return el('section', { class: 'intro', 'aria-labelledby': 'intro-heading' }, [
    el('h2', { id: 'intro-heading', text: 'What this is, in plain language' }),
    para(
      'When you type a name, something has to tell your computer which address it belongs to. DNS does that, and by default it does it with no signatures at all — whoever answers first is believed.'
    ),
    para(
      'DNSSEC adds signatures. Every zone signs its own records, and its parent publishes a fingerprint of the zone’s key, so a chain of vouching runs from a single key built into your resolver all the way down to the answer. This is a completely separate trust system from the certificates your browser checks; the two share no keys and no authorities.'
    ),
    para(
      'The hard part is signing a NEGATIVE. A zone cannot sign “that name does not exist” for every name that does not exist — there are infinitely many. So it signs the GAPS between the names that do exist, and hands you the neighbours as proof. That works, and it is also a directory. Following the gaps is the fourth tab, and it is the thing to look at first.'
    ),
  ]);
}

function scopeNote(): HTMLElement {
  return el('section', { class: 'scope-note', 'aria-label': 'Scope and honesty' }, [
    el('p', {}, [
      el('strong', { text: 'Not production crypto — a teaching demo. ' }),
      'The signatures are real: WebCrypto verifies RSASHA256 and ECDSA P-256, ',
      el('code', { text: '@noble/curves' }),
      ' verifies Ed25519, and every RFC known-answer test in the repository passes. The real-world chain is a ',
      el('strong', { text: 'pinned capture' }),
      ' taken with ',
      el('code', { text: 'dig' }),
      ' and committed to the repository — nothing here queries DNS at run time, and it is validated against the instant it was captured.',
    ]),
    el('p', {}, [
      el('strong', { text: 'What it does NOT prove. ' }),
      'A green result here says these particular records verified under these particular keys at a chosen instant. It says nothing about whether the answer is the one you wanted, whether the zone operator is honest, or whether the name is safe to visit. DNSSEC authenticates ',
      el('em', { text: 'origin and integrity' }),
      ' and never confidentiality: queries and answers travel in the clear whether or not they validate, which is why DNS-over-HTTPS and DNS-over-TLS exist as separate mechanisms.',
    ]),
    el('p', { id: 'ech-note' }, [
      el('strong', { text: 'One cross-link, stated carefully. ' }),
      'Encrypted ClientHello publishes its configuration in a DNS HTTPS or SVCB record, so it is often assumed to be built on this chain. It is not. RFC 9849 section 10.2 specifies that ECH "supports delivery of configurations through the DNS using SVCB or HTTPS records without requiring any verifiable authenticity or provenance information", and names DNSSEC and encrypted DNS transport as two separate defences against DNS tampering — ECH gets its authenticity from the TLS certificate for the configuration\u2019s public name. DNSSEC is an available protection for the ECHConfig, not the source of its authenticity.',
    ]),
    el('p', {}, [
      el('strong', { text: 'Out of scope. ' }),
      'No resolver, no caching, no network, no zone transfers, no DoH/DoT. Algorithms 8, 13 and 15 are implemented; every other real algorithm is reported as unsupported rather than as a forgery. The in-page hierarchy uses ',
      el('code', { text: 'example.' }),
      ' (RFC 2606) and RFC 5737 documentation addresses, and its private keys are published in the repository on purpose — they protect nothing.',
    ]),
  ]);
}

export function mount(root: HTMLElement): void {
  const main = el('main', { id: 'main' });
  const tablist = el('div', {
    class: 'tablist',
    role: 'tablist',
    'aria-label': 'DNSSEC exhibits',
  });
  const panels: HTMLElement[] = [];
  const rendered = new Set<string>();

  const activate = (index: number, focus = false): void => {
    TABS.forEach((tab, i) => {
      const button = tablist.children[i] as HTMLButtonElement | undefined;
      const panel = panels[i];
      if (!button || !panel) return;
      const selected = i === index;
      button.setAttribute('aria-selected', selected ? 'true' : 'false');
      button.tabIndex = selected ? 0 : -1;
      panel.hidden = !selected;
      if (selected && !rendered.has(tab.id)) {
        rendered.add(tab.id);
        void tab.render(panel);
      }
      if (selected && focus) button.focus();
    });
  };

  TABS.forEach((tab, index) => {
    const button = el('button', {
      type: 'button',
      class: 'tab-btn',
      role: 'tab',
      id: `tab-${tab.id}`,
      'aria-controls': `panel-${tab.id}`,
      'aria-selected': index === 0 ? 'true' : 'false',
      tabindex: index === 0 ? '0' : '-1',
    }, [
      el('span', { class: 'tab-index', 'aria-hidden': 'true', text: `${index + 1}` }),
      tab.label,
    ]);
    button.addEventListener('click', () => activate(index));
    button.addEventListener('keydown', (event) => {
      const keys: Record<string, number> = {
        ArrowRight: (index + 1) % TABS.length,
        ArrowLeft: (index - 1 + TABS.length) % TABS.length,
        Home: 0,
        End: TABS.length - 1,
      };
      const next = keys[event.key];
      if (next === undefined) return;
      event.preventDefault();
      activate(next, true);
    });
    tablist.append(button);

    const panel = el('section', {
      class: 'panel',
      role: 'tabpanel',
      id: `panel-${tab.id}`,
      'aria-labelledby': `tab-${tab.id}`,
      tabindex: '0',
    });
    panel.hidden = index !== 0;
    panels.push(panel);
  });

  const tabs = el('div', { class: 'tabs' }, [
    el('nav', { 'aria-label': 'Exhibit navigation' }, [tablist]),
    ...panels,
  ]);

  main.append(intro(), tabs, scopeNote());
  root.append(hero(), main, footer());
  activate(0);
}

function footer(): HTMLElement {
  return el('footer', { class: 'scripture-footer' }, [
    el('p', {
      text: 'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    }),
  ]);
}
