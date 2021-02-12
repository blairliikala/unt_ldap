<?php

$lang = array(

	'ldap_character_encode'     => 'LDAP encoding type',
	'use_ldap_account_creation' => 'Use LDAP for account creation',
	'role_facultystaff'			=> '<h2>Primary Role: Faculty/Staff</h2>',
	'role_student'				=> '<h2>Primary Role: Students</h2>',
	'role_alumni'				=> '<h2>Primary Role: Alumni and Gradudates</h2>',
	'role_guest'				=> '<h2>Primary Role: Guest</h2>',
	'role_edu'					=> '<h2>Primary Role: Educators</h2>',
	'role_discontinued'			=> '<h2>Primary Role: Discontinued</h2>',
	'role_editors'				=> '<h2>Primary Role: Editors</h2><p>Those who can access CP and edit entries, typically student workers.</p>',
	'role_affiliate'			=> '<h2>Primary Role: Affiliate</h2><p>Contractors and other.</p>',

	'first_name_field_id'       => '<h2>First Name Field</h2>',
	'last_name_field_id'        => '<h2>Last Name Field</h2>',
	'ignore_ldap_role_field_id' => '<h2>Ignore Primary Role Assigments Field</h2><p>The custom member field that flags a member not to be sorted into a group using LDAP and this add-ons sorting process.</p>',
	'ferpa_withdraw_field_id'   => '<h2>FERPA protect information field</h2><p>Used in templates for opting-out the member ID to be used in other services like stats and tracking.</p>',
	'ldap_dump_field_id'	    => '<h2>LDAP Log Dump Field</h2>',
	'protected_roles'			=> '<h2>(v5) Roles that will not use LDAP to Authenticate</h2><p>Members in this group will use EEs build-in member system.</p>',
	'ldap_affiliation_id'	    => '<h2>Affiliation ID</h2><p>LDAP Affiliation field.</p>',
	'ldap_url'					=> 'LDAP URL  <p><small>ldaps://example.com:1234, ldap://example2.com:1234</small></p>',
	'exempt_from_role_changes'  => '<h2>Disable Auto Role Sorting</h2><p>Members can get in, but not automatically assigned out.  This only applies to LDAP-authentication roles.',
	'use_LDAP_rolegroup_id'	    => '<h2>Role Groups that use LDAP to authenticate.</h2><p>Selecting a group will include all associated roles to use LDAP for authentication.</p>',

	'yes_ldap_account_creation' => 'Yes',
	'no_ldap_account_creation'  => 'No',

	'' => ''
);
// end array