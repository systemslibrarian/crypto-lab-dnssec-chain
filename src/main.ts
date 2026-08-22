/**
 * Entry point.
 *
 * Content mounts at `#app`, which is also the skip link's target and the
 * wrapper the shared top bar expects. There is no theme logic here: dark is
 * the only theme and `index.html` pins it before first paint.
 */

import './style.css';
import { mount } from './ui/app.ts';

const root = document.getElementById('app');
if (!root) throw new Error('#app is missing from index.html');
mount(root);
