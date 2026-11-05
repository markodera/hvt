#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import("../dist/index.js").catch((err) => {
  console.error(err);
  process.exit(1);
});
