// SPDX-License-Identifier: GPL-2.0-only
/// Validate scoped_masked_user*access() scopes
///
// Confidence: Zero
// Options: --no-includes --include-headers

virtual context
virtual report
virtual org

@initialize:python@
@@

scopemap = {
  'scoped_user_read_access_size'  : 'scoped_user_read_access',
  'scoped_user_write_access_size' : 'scoped_user_write_access',
  'scoped_user_rw_access_size'    : 'scoped_user_rw_access',
}

# Most common accessors. Incomplete list
noaccessmap = {
  'scoped_user_read_access'       : ('unsafe_put_user', 'unsafe_copy_to_user'),
  'scoped_user_write_access'      : ('unsafe_get_user', 'unsafe_copy_from_user'),
}

# Most common accessors. Incomplete list
ptrmap = {
  'unsafe_put_user'			 : 1,
  'unsafe_get_user'			 : 1,
  'unsafe_copy_to_user'		 	 : 0,
  'unsafe_copy_from_user'		 : 0,
}

print_mode = None

def pr_err(pos, msg):
   if print_mode == 'R':
      coccilib.report.print_report(pos[0], msg)
   elif print_mode == 'O':
      cocci.print_main(msg, pos)

@r0 depends on report || org@
iterator name scoped_user_read_access,
	      scoped_user_read_access_size,
	      scoped_user_write_access,
	      scoped_user_write_access_size,
	      scoped_user_rw_access,
	      scoped_user_rw_access_size;
iterator scope;
statement S;
@@

(
(
scoped_user_read_access(...) S
|
scoped_user_read_access_size(...) S
|
scoped_user_write_access(...) S
|
scoped_user_write_access_size(...) S
|
scoped_user_rw_access(...) S
|
scoped_user_rw_access_size(...) S
)
&
scope(...) S
)

@script:python depends on r0 && report@
@@
print_mode = 'R'

@script:python depends on r0 && org@
@@
print_mode = 'O'

@r1@
expression sp, a0, a1;
iterator r0.scope;
identifier ac;
position p;
@@

  scope(sp,...) {
    <...
    ac@p(a0, a1, ...);
    ...>
  }

@script:python@
pos << r1.p;
scope << r0.scope;
ac << r1.ac;
sp << r1.sp;
a0 << r1.a0;
a1 << r1.a1;
@@

scope = scopemap.get(scope, scope)
if ac in noaccessmap.get(scope, []):
   pr_err(pos, 'ERROR: Invalid access mode %s() in %s()' %(ac, scope))

if ac in ptrmap:
   ap = (a0, a1)[ptrmap[ac]]
   if sp != ap.lstrip('&').split('->')[0].strip():
      pr_err(pos, 'ERROR: Invalid pointer for %s(%s) in %s(%s)' %(ac, ap, scope, sp))
