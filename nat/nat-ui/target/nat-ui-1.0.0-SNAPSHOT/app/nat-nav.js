/*
  (c) Copyright 2012 Hewlett-Packard Development Company, L.P.
  Autogenerated
 */

// JSLint directive...
/*global $: false, SKI: false */

(function (api) {
    'use strict';

    var f = api.fn,          // general functions API
        nav = api.nav;       // navigation model API

    f.trace('including nat-nav.js');

    // Add a new category and new item
    nav.insertCategoryAfter('c-tasks', 'c-nat', [
        nav.item('n-nat', 'nat', 'square')
    ]);

    // Add a new item to an existing category
    nav.insertItemsBefore('n-exportLogs', [
        nav.item('n-nat-task', 'natTask', 'square')
    ]);

}(SKI));
