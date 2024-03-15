// SPDX-License-Identifier: GPL-2.0-only
/// Use capable_any rather than chaining capable and order CAP_SYS_ADMIN last
///
// Confidence: High
// Copyright: (C) 2024 Christian Göttsche.
// URL: https://coccinelle.gitlabpages.inria.fr/website
// Options: --no-includes --include-headers
// Keywords: capable, capable_any, ns_capable, ns_capable_any, sockopt_ns_capable, sockopt_ns_capable_any

virtual patch
virtual context
virtual org
virtual report

//----------------------------------------------------------
//  For patch mode
//----------------------------------------------------------

@ depends on patch@
binary operator op;
expression cap1,cap2,E;
expression ns;
@@

(
-  capable(cap1) || capable(cap2)
+  capable_any(cap1, cap2)
|
-  E op capable(cap1) || capable(cap2)
+  E op capable_any(cap1, cap2)
|
-  !capable(cap1) && !capable(cap2)
+  !capable_any(cap1, cap2)
|
-  E op !capable(cap1) && !capable(cap2)
+  E op !capable_any(cap1, cap2)
|
-  ns_capable(ns, cap1) || ns_capable(ns, cap2)
+  ns_capable_any(ns, cap1, cap2)
|
-  E op ns_capable(ns, cap1) || ns_capable(ns, cap2)
+  E op ns_capable_any(ns, cap1, cap2)
|
-  !ns_capable(ns, cap1) && !ns_capable(ns, cap2)
+  !ns_capable_any(ns, cap1, cap2)
|
-  E op !ns_capable(ns, cap1) && !ns_capable(ns, cap2)
+  E op !ns_capable_any(ns, cap1, cap2)
|
-  sockopt_ns_capable(ns, cap1) || sockopt_ns_capable(ns, cap2)
+  sockopt_ns_capable_any(ns, cap1, cap2)
|
-  E op sockopt_ns_capable(ns, cap1) || sockopt_ns_capable(ns, cap2)
+  E op sockopt_ns_capable_any(ns, cap1, cap2)
|
-  !sockopt_ns_capable(ns, cap1) && !sockopt_ns_capable(ns, cap2)
+  !sockopt_ns_capable_any(ns, cap1, cap2)
|
-  E op !sockopt_ns_capable(ns, cap1) && !sockopt_ns_capable(ns, cap2)
+  E op !sockopt_ns_capable_any(ns, cap1, cap2)
)

@ depends on patch@
identifier func = { capable_any, ns_capable_any, sockopt_ns_capable_any };
expression cap;
expression ns;
@@

(
-  func(CAP_SYS_ADMIN, cap)
+  func(cap, CAP_SYS_ADMIN)
|
-  func(ns, CAP_SYS_ADMIN, cap)
+  func(ns, cap, CAP_SYS_ADMIN)
)

//----------------------------------------------------------
//  For context mode
//----------------------------------------------------------

@r1 depends on !patch exists@
binary operator op;
expression cap1,cap2,E;
expression ns;
position p1,p2;
@@

(
*  capable@p1(cap1) || capable@p2(cap2)
|
*  E op capable@p1(cap1) || capable@p2(cap2)
|
*  !capable@p1(cap1) && !capable@p2(cap2)
|
*  E op !capable@p1(cap1) && !capable@p2(cap2)
|
*  ns_capable@p1(ns, cap1) || ns_capable@p2(ns, cap2)
|
*  E op ns_capable@p1(ns, cap1) || ns_capable@p2(ns, cap2)
|
*  !ns_capable@p1(ns, cap1) && !ns_capable@p2(ns, cap2)
|
*  E op !ns_capable@p1(ns, cap1) && !ns_capable@p2(ns, cap2)
|
*  sockopt_ns_capable@p1(ns, cap1) || sockopt_ns_capable@p2(ns, cap2)
|
*  E op sockopt_ns_capable@p1(ns, cap1) || sockopt_ns_capable@p2(ns, cap2)
|
*  !sockopt_ns_capable@p1(ns, cap1) && !sockopt_ns_capable@p2(ns, cap2)
|
*  E op !sockopt_ns_capable@p1(ns, cap1) && !sockopt_ns_capable@p2(ns, cap2)
)

@r2 depends on !patch exists@
identifier func = { capable_any, ns_capable_any, sockopt_ns_capable_any };
expression cap;
expression ns;
position p;
@@

(
*  func@p(CAP_SYS_ADMIN, cap)
|
*  func@p(ns, CAP_SYS_ADMIN, cap)
)

//----------------------------------------------------------
//  For org mode
//----------------------------------------------------------

@script:python depends on org@
p1 << r1.p1;
p2 << r1.p2;
@@

cocci.print_main("WARNING opportunity for capable_any",p1)
cocci.print_secs("chained capable",p2)

@script:python depends on org@
p << r2.p;
f << r2.func;
@@

cocci.print_main("WARNING " + f + " arguments should be reordered",p)

//----------------------------------------------------------
//  For report mode
//----------------------------------------------------------

@script:python depends on report@
p1 << r1.p1;
p2 << r1.p2;
@@

msg = "WARNING opportunity for capable_any (chained capable line %s)" % (p2[0].line)
coccilib.report.print_report(p1[0], msg)

@script:python depends on report@
p << r2.p;
f << r2.func;
@@

msg = "WARNING %s arguments should be reordered" % (f)
coccilib.report.print_report(p[0], msg)
