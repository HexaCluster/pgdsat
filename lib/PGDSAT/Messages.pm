package PGDSAT::Messages;
#------------------------------------------------------------------------------
# Project  : PostgreSQL Database Security Assement Tool
# Name     : PGDSAT/Messages.pm
# Language : Perl
# Authors  : Gilles Darold
# Copyright: Copyright (c) 2024 HexaCluster Corp
# Function : Language module to import the securiy check description
#------------------------------------------------------------------------------
use vars qw($VERSION %AUDIT_MSG);
use strict;

$VERSION = '1.1';

# The numbering here try to follow the numbering in the PGDSAT::Labels file
# but it is not requires. We just keep the numbering from PGDSAT::Labels
# to easily find the relation between the messages and the tests.

%AUDIT_MSG = (
	'en_US' => {
		'0.1' => { 'errmsg' => 'Test passed'},
		'1.1' => { 'errmsg' => 'No PostgreSQL packages found.' },
		'1.2' => { 'errmsg' => 'PostgreSQL packages are not from the PGDG repository.' },
		'1.3' => { 'errmsg' => 'No internet access to https://www.postgresql.org/.' },
		'1.4' => { 'errmsg' => 'This PostgreSQL version, v%s, is no more supported.' },
		'1.5' => { 'errmsg' => 'This PostgreSQL version, v%s, is not the last one of this branch (%s)' },
		'1.6' => { 'errmsg' => 'See <a href="https://why-upgrade.depesz.com/show?from=%s&to=%s" target="_new">Why upgrade</a>.' },
		'1.7' => { 'errmsg' => 'PostgreSQL version %s, is not enabled as a systemd service.' },
		'1.8' => { 'errmsg' => 'PostgreSQL systemd service must not be enabled when patroni is used.' },
		'1.9' => { 'errmsg' => 'Wrong or no base directory found, the PGDATA (%s) must be initialized first (see initdb).' },
		'1.10' => { 'errmsg' => 'The version of the PGDATA (%s) does not correspond to the PostgreSQL cluster version; You need to upgrade the PGDATA v%s to v%s first.' },
		'1.11' => { 'errmsg' => 'Checksum are not enabled in PGDATA %s.' },
		'1.12' => { 'errmsg' => 'Subdirectory pg_wal is not on a separate partition than the PGDATA %s.' },
		'1.13' => { 'errmsg' => 'Subdirectory for temporary file is not on a separate partition than the PGDATA.' },
		'1.14' => { 'errmsg' => 'Can not get information about encrypted partition, command lsblk is missing on this host.' },
		'1.15' => { 'errmsg' => 'PostgreSQL version check was disabled (--no-pg-version-check) can not look for minor version upgrade.' },
		'1.16' => { 'errmsg' => 'Tablespace location %s should not be inside the data directory.' },
		'1.17' => { 'errmsg' => 'PostgreSQL version %s, is enabled as a systemd service.' },
		'2.1' => { 'errmsg' => 'The umask must be 0077 or more restrictive for the postgres user. Currently it is set to %s.' },
		'2.2' => { 'errmsg' => 'Permissions of the PGDATA are not secure: %s, must be drwx------.' },
		'2.4' => { 'errmsg' => 'Permissions of the pg_hba.conf file (%s) are not secure: %s, must be -rw-r----- or -rw-------.' },
		'2.5' => { 'errmsg' => 'Permission on Unix socket %s should be more restrictive, for example: 0770 or 0700. Currently it is set to 0777.' },
		'3.1' => { 'errmsg' => 'Setting \'log_destination\' is not set, logging will be lost.' },
		'3.2' => { 'errmsg' => 'Setting \'logging_collector\' should be enabled instead of using syslog.' },
		'3.3' => { 'errmsg' => 'Setting \'logging_collector\' must be enabled when \'log_destination\' is not set to syslog, logging will be lost.' },
		'3.4' => { 'errmsg' => 'Setting \'log_directory\' must be set, currently writes will be done in / and logging will be lost.' },
		'3.5' => { 'errmsg' => 'Setting \'log_filename\' must be set, currently logging will be lost.' },
		'3.6' => { 'errmsg' => 'Setting \'log_file_mode\' should be set to \'0600\', current value is %s.' },
		'3.7' => { 'errmsg' => 'Setting \'log_truncate_on_rotation\' should be enabled.' },
		'3.11' => { 'errmsg' => 'Setting \'syslog_sequence_numbers\' should be enabled, some messages can be lost.' },
		'3.12' => { 'errmsg' => 'Setting \'syslog_split_messages\' should be enabled, some messages can be truncated.' },
		'3.14' => { 'errmsg' => 'Setting \'log_min_messages\' should be set to \'warning\' to avoid tracing too many or too few messages.' },
		'3.15' => { 'errmsg' => 'Setting \'log_min_error_statement\' should be set to \'error\' to avoid tracing too many or too few messages.' },
		'3.16' => { 'errmsg' => 'Setting \'debug_print_parse\' should be disabled.' },
		'3.17' => { 'errmsg' => 'Setting \'debug_print_rewritten\' should be disabled.' },
		'3.18' => { 'errmsg' => 'Setting \'debug_print_plan\' should be disabled.' },
		'3.19' => { 'errmsg' => 'Setting \'debug_pretty_print\' should be enabled.' },
		'3.20' => { 'errmsg' => 'Setting \'log_connections\' should be enabled.' },
		'3.21' => { 'errmsg' => 'Setting \'log_disconnections\' should be enabled.' },
		'3.22' => { 'errmsg' => 'Setting \'log_error_verbosity\' should be set to \'verbose\'.' },
		'3.23' => { 'errmsg' => 'Setting \'log_hostname\' should be disabled.' },
		'3.24' => { 'errmsg' => 'Setting \'log_line_prefix\' should containt at least \'%%m [%%p]: db=%%d,user=%%u,app=%%a,client=%%h \' (for stderr logging). For syslog logging, the prefix should include \'user=%%u,db=%%d,app=%%a,client=%%h \'.' },
		'3.25' => { 'errmsg' => 'Setting \'log_statement\' should at least be set to \'ddl\'.' },
		'3.26' => { 'errmsg' => 'Setting \'log_timezone\' should be set to \'GMT\' or \'UTC\'.' },
		'3.27' => { 'errmsg' => 'Setting \'log_directory\' should use a location that is not in the PGDATA.' },
		'3.28' => { 'errmsg' => 'PostgreSQL extension pgAudit should be used.' },
		'3.29' => { 'errmsg' => 'PostgreSQL extension pgAudit is not well configured, \'pgaudit.log\' setting shoud contain \'ddl\' and \'write\'.' },
		'4.2' => { 'errmsg' => 'There are more than one PostgreSQL superuser.' },
		'4.5' => { 'errmsg' => 'Some PostgreSQL user have Bypass RLS enabled.' },
		'4.8' => { 'errmsg' => 'Schema public can be used by anyone in database %s.' },
		'5.1' => { 'errmsg' => 'Can not find pg_hba.conf file "%s".' },
		'5.2' => { 'errmsg' => 'Can not read pg_hba.conf file "%s", reason: "%s".' },
		'5.3' => { 'errmsg' => 'Can not open directory "%s", reason: "%s".' },
		'5.4' => { 'errmsg' => 'The use of the "%s" authentication method must not be used. See line %s in file %s.' },
		'5.5' => { 'errmsg' => 'The use of the "md5" authentication method is vulnerable to packet replay attacks. See line %s in file %s.' },
		'5.6' => { 'errmsg' => 'The use of the "ident" authentication method is insecure, the client running the ident server should be considered as untrust. See line %s in file %s.' },
		'5.7' => { 'errmsg' => 'Use %s or any of the external authentication method (gss, sspi, pam, ldap, radius or cert) instead.' },
		'5.8' => { 'errmsg' => 'No password difficulty enforcement library used. Consider using the credcheck or passwordcheck PostgreSQL extension.' },
		'5.9' => { 'errmsg' => 'Setting \'authentication_timeout\' should be <= 60s.' },
		'5.10' => { 'errmsg' => 'You should add an authentication failure delay to prevent brute force attack. See PostgreSQL extension credcheck or auth_delay.' },
		'5.11' => { 'errmsg' => 'The use of the "host" connection type should be rejected when "hostssl" or "hostgssenc" is used. See line(s) %s in pg_hba.conf.' },
		'5.12' => { 'errmsg' => 'Use of ssl encryption for all remote connection should be used, see "hostssl" and "hostgssenc" connection type.' },
		'5.13' => { 'errmsg' => 'The use of %s \'%s\' correspond to any source. See line %s in file %s.' },
		'5.14' => { 'errmsg' => 'The use of %s \'%s\' correspond to a too huge Ip range. See line %s in file %s.' },
		'5.15' => { 'errmsg' => 'You should be more specific and give the database and users allowed to connect, not "all". See line %s in file %s.' },
		'5.16' => { 'errmsg' => 'You should not allow superusers to connect remotely, only from local and peer authentication. See line %s in file %s.' },
		'5.17' => { 'errmsg' => 'parameter \'password_encryption\' should be set to \'scram-sha-256\', not \'%s\'.' },
		'6.2' => { 'errmsg' => 'Setting \'%s\' must be disabled.' },
		'6.3' => { 'errmsg' => 'Setting \'%s\' must be enabled.' },
		'6.4' => { 'errmsg' => 'Setting \'post_auth_delay\' must be set to 0.' },
		'6.5' => { 'errmsg' => 'Installation of FIPS modules is not completed.' },
		'6.6' => { 'errmsg' => 'See <a href="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies" target="_new">"switching the system to fips mode"</a> to enable FIPS mode' },
		'6.7' => { 'errmsg' => 'TLS is not enabled. Setting \'ssl\' should be activated.' },
		'6.8' => { 'errmsg' => 'Setting \'ssl_min_protocol_version\' should be TLS v1.3 or newer.' },
		'6.9' => { 'errmsg' => 'The SSL certificate should have a passphrase and setting \'ssl_passphrase_command\' should be set.' },
		'6.10' => { 'errmsg' => 'To enforce TLS authentication for the server, appropriate "hostssl" or "hostgssenc" records must be added to the pg_hba.conf file and "host" connections rejected.' },
		'6.11' => { 'errmsg' => 'Extensions pgcrypto or pgsodium are not installed.' },
		'6.12' => { 'errmsg' => 'Extensions pg_anonymize or anon are not installed.' },
		'7.1' => { 'errmsg' => 'A replication-only user should be created.' },
		'7.2' => { 'errmsg' => 'Setting \'log_replication_commands\' should be enabled.' },
		'7.4' => { 'errmsg' => 'WAL archiving is not activated. Setting \'archive_mode\' must be enabled.' },
		'7.5' => { 'errmsg' => 'Settings \'archive_command\' or \'archive_library\' must be enabled.' },
		'7.6' => { 'errmsg' => 'Setting \'primary_conninfo\' must enforce TLS encryption of the replication (sslmode=required).' },
		'7.7' => { 'errmsg' => 'Setting \'primary_conninfo\' should enable SSL compression (sslcompression=1).' },
		'8.2' => { 'errmsg' => 'The backup tool \'pgBackRest\' is not installed.' },
		'8.3' => { 'errmsg' => 'No stanzas exist for \'pgBackRest\'.' },

	},
#-----------------------------------------------------------------------------
	'fr_FR' => {
#-----------------------------------------------------------------------------
		'0.1' => { 'errmsg' => 'Test réussi'},
		'1.1' => { 'errmsg' => 'Aucun paquet PostgreSQL trouvé.' },
		'1.2' => { 'errmsg' => 'Les packages PostgreSQL ne proviennent pas du référentiel PGDG.' },
		'1.3' => { 'errmsg' => 'Pas d\'accès Internet à https://www.postgresql.org/.' },
		'1.4' => { 'errmsg' => 'Cette version de PostgreSQL, v%s, n\'est plus prise en charge.' },
		'1.5' => { 'errmsg' => 'Cette version de PostgreSQL, v%s, n\'est pas la dernière de cette branche (%s)' },
		'1.6' => { 'errmsg' => 'Voir Pourquoi mettre à niveau .' },
		'1.7' => { 'errmsg' => 'La version %s de PostgreSQL n\'est pas activée en tant que service systemd.' },
		'1.8' => { 'errmsg' => 'Le service systemd PostgreSQL ne doit pas être activé lorsque patroni est utilisé.' },
		'1.9' => { 'errmsg' => 'Mauvais ou aucun répertoire de base trouvé, le PGDATA (%s) doit d\'abord être initialisé (voir initdb).' },
		'1.10' => { 'errmsg' => 'La version du PGDATA (%s) ne correspond pas à la version du cluster PostgreSQL ; Vous devez d\'abord mettre à niveau le PGDATA v%s vers v%s.' },
		'1.11' => { 'errmsg' => 'Les sommes de contrôle ne sont pas activées dans PGDATA %s.' },
		'1.12' => { 'errmsg' => 'Le sous-répertoire pg_wal ne se trouve pas sur une partition distincte de celle du PGDATA %s.' },
		'1.13' => { 'errmsg' => 'Le sous-répertoire du fichier temporaire ne se trouve pas sur une partition distincte de celle de PGDATA.' },
		'1.14' => { 'errmsg' => 'Impossible d\'obtenir des informations sur la partition chiffrée, la commande lsblk est manquante sur cet hôte.' },
		'1.15' => { 'errmsg' => 'La vérification de la version PostgreSQL était désactivée (--no-pg-version-check) ne peut pas rechercher une mise à niveau de version mineure.' },
		'1.16' => { 'errmsg' => 'La destination du tablespace %s ne devrait pas être dans le répertoire des données.' },
		'1.17' => { 'errmsg' => 'La version %s de PostgreSQL est activée en tant que service systemd.' },
		'2.1' => { 'errmsg' => 'L\'umask doit être 0077 ou plus restrictif pour l\'utilisateur postgres. Actuellement, il est défini sur %s.' },
		'2.2' => { 'errmsg' => 'Les autorisations de PGDATA ne sont pas sécurisées : %s, doivent être drwx------.' },
		'2.4' => { 'errmsg' => 'Les autorisations du fichier pg_hba.conf (%s) ne sont pas sécurisées : %s, doivent être -rw-r----- ou -rw------ -.' },
		'2.5' => { 'errmsg' => 'Les autorisations de la socket Unix %s devraient être plus restrictives, par exemple: 0770 ou 0700. Actuellement elles ont positionnées à 0777.' },
		'3.1' => { 'errmsg' => 'Le paramètre \'log_destination\' n\'est pas défini, la journalisation sera perdue.' },
		'3.2' => { 'errmsg' => 'Le paramètre \'logging_collector\' doit être activé au lieu d\'utiliser syslog.' },
		'3.3' => { 'errmsg' => 'Le paramètre \'logging_collector\' doit être activé lorsque \'log_destination\' n\'est pas défini sur syslog, la journalisation sera perdue.' },
		'3.4' => { 'errmsg' => 'Le paramètre \'log_directory\' doit être défini, actuellement les écritures seront effectuées dans / et la journalisation sera perdue.' },
		'3.5' => { 'errmsg' => 'Le paramètre \'log_filename\' doit être défini, la journalisation actuelle sera perdue.' },
		'3.6' => { 'errmsg' => 'Le paramètre \'log_file_mode\' doit être défini sur \'0600\', la valeur actuelle est %s.' },
		'3.7' => { 'errmsg' => 'Le paramètre \'log_truncate_on_rotation\' doit être activé.' },
		'3.11' => { 'errmsg' => 'Le paramètre \'syslog_sequence_numbers\' doit être activé, certains messages peuvent être perdus.' },
		'3.12' => { 'errmsg' => 'Le paramètre \'syslog_split_messages\' doit être activé, certains messages peuvent être tronqués.' },
		'3.14' => { 'errmsg' => 'Le paramètre \'log_min_messages\' doit être défini sur \'warning\' pour éviter de tracer trop ou trop peu de messages.' },
		'3.15' => { 'errmsg' => 'Le paramètre \'log_min_error_statement\' doit être défini sur \'error\' pour éviter de tracer trop ou trop peu de messages.' },
		'3.16' => { 'errmsg' => 'Le paramètre \'debug_print_parse\' doit être désactivé.' },
		'3.17' => { 'errmsg' => 'Le paramètre \'debug_print_rewriting\' doit être désactivé.' },
		'3.18' => { 'errmsg' => 'Le paramètre \'debug_print_plan\' doit être désactivé.' },
		'3.19' => { 'errmsg' => 'Le paramètre \'debug_pretty_print\' doit être activé.' },
		'3.20' => { 'errmsg' => 'Le paramètre \'log_connections\' doit être activé.' },
		'3.21' => { 'errmsg' => 'Le paramètre \'log_disconnections\' doit être activé.' },
		'3.22' => { 'errmsg' => 'Le paramètre \'log_error_verbosity\' doit être défini sur \'verbose\'.' },
		'3.23' => { 'errmsg' => 'Le paramètre \'log_hostname\' doit être désactivé.' },
		'3.24' => { 'errmsg' => 'Le paramètre \'log_line_prefix\' doit contenir au moins \'%%m [%%p] : db=%%d,user=%%u,app=%%a ,client=%%h \' (pour la journalisation stderr). Pour la journalisation Syslog, le préfixe doit inclure \'user=%%u,db=%%d,app=%%a,client=%%h \'.' },
		'3.25' => { 'errmsg' => 'Le paramètre \'log_statement\' doit au moins être défini sur \'ddl\'.' },
		'3.26' => { 'errmsg' => 'Le paramètre \'log_timezone\' doit être défini sur \'GMT\' ou \'UTC\'.' },
		'3.27' => { 'errmsg' => 'Le paramètre \'log_directory\' doit utiliser un emplacement qui ne figure pas dans PGDATA.' },
		'3.28' => { 'errmsg' => 'L\'extension PostgreSQL pgAudit doit être utilisée.' },
		'3.29' => { 'errmsg' => 'L\'extension PostgreSQL pgAudit n\'est pas bien configurée, le paramètre \'pgaudit.log\' doit contenir \'ddl\' et \'write\'.' },
		'4.2' => { 'errmsg' => 'Il existe plusieurs superutilisateurs PostgreSQL.' },
		'4.5' => { 'errmsg' => 'Certains utilisateurs de PostgreSQL ont activé Bypass RLS.' },
		'4.8' => { 'errmsg' => 'Le schema public peut être utilisé par tout le monde dans la base %s.' },
		'5.1' => { 'errmsg' => 'Impossible de trouver le fichier pg_hba.conf "%s".' },
		'5.2' => { 'errmsg' => 'Impossible de lire le fichier pg_hba.conf "%s", raison : "%s".' },
		'5.3' => { 'errmsg' => 'Impossible d\'ouvrir le répertoire "%s", raison : "%s".' },
		'5.4' => { 'errmsg' => 'L\'utilisation de la méthode d\'authentification "%s" ne doit pas être utilisée. Voir la ligne %s dans le fichier %s.' },
		'5.5' => { 'errmsg' => 'L\'utilisation de la méthode d\'authentification "md5" est vulnérable aux attaques par relecture de paquets. Voir la ligne %s dans le fichier %s.' },
		'5.6' => { 'errmsg' => 'L\'utilisation de la méthode d\'authentification "ident" n\'est pas sécurisée, le client exécutant le serveur d\'identification doit être considéré comme non fiable. Voir la ligne %s dans le fichier %s.' },
		'5.7' => { 'errmsg' => 'Utilisez %s ou n\'importe quelle méthode d\'authentification externe (gss, sspi, pam, ldap, radius ou cert) à la place.' },
		'5.8' => { 'errmsg' => 'Aucune bibliothèque d\'application de difficultés de mot de passe utilisée. Pensez à utiliser l\'extension PostgreSQL credcheck ou passwordcheck.' },
		'5.9' => { 'errmsg' => 'Le paramètre \'authentication_timeout\' doit être <= 60 s.' },
		'5.10' => { 'errmsg' => 'Vous devez ajouter un délai d\'échec d\'authentification pour empêcher une attaque par force brute. Voir l\'extension PostgreSQL credcheck ou auth_delay.' },
		'5.11' => { 'errmsg' => 'L\'utilisation du type de connexion "host" doit être rejetée lorsque "hostssl" ou "hostgssenc" est utilisé. Voir la(les) ligne(s) %s dans pg_hba.conf.' },
		'5.12' => { 'errmsg' => 'L\'utilisation du cryptage SSL pour toutes les connexions à distance doit être utilisée, voir les types de connexion "hostssl" et "hostgssenc".' },
		'5.13' => { 'errmsg' => 'L\'utilisation de %s \'%s\' correspond à n\'importe quelle source. Voir la ligne %s dans le fichier %s.' },
		'5.14' => { 'errmsg' => 'L\'utilisation de %s \'%s\' correspond à une plage d\'Ip trop grande. Voir la ligne %s dans le fichier %s.' },
		'5.15' => { 'errmsg' => 'Vous devriez être plus précis et donner la base de données et les utilisateurs autorisés à se connecter, pas "tous". Voir la ligne %s dans le fichier %s.' },
		'5.16' => { 'errmsg' => 'Vous ne devez pas autoriser les superutilisateurs à se connecter à distance, uniquement à partir d\'une authentification locale et homologue. Voir la ligne %s dans le fichier %s.' },
		'6.2' => { 'errmsg' => 'Le paramètre \'%s\' doit être désactivé.' },
		'6.3' => { 'errmsg' => 'Le paramètre \'%s\' doit être activé.' },
		'6.4' => { 'errmsg' => 'Le paramètre \'post_auth_delay\' doit être défini sur 0.' },
		'6.5' => { 'errmsg' => 'L\'installation des modules FIPS n\'est pas terminée.' },
		'6.6' => { 'errmsg' => 'Voir <a href="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies" target="_new">"passer le système en mode fips"</a> pour activer le mode FIPS' },
		'6.7' => { 'errmsg' => 'TLS n\'est pas activé. Le paramètre \'ssl\' doit être activé.' },
		'6.8' => { 'errmsg' => 'Le paramètre \'ssl_min_protocol_version\' doit être TLS v1.3 ou plus récent.' },
		'6.9' => { 'errmsg' => 'Le certificat SSL doit avoir une phrase secrète et le paramètre \'ssl_passphrase_command\' doit être défini.' },
		'6.10' => { 'errmsg' => 'Pour appliquer l\'authentification TLS pour le serveur, les enregistrements "hostssl" ou "hostgssenc" appropriés doivent être ajoutés au fichier pg_hba.conf et les connexions "host" rejetées.' },
		'6.11' => { 'errmsg' => 'Les extensions pgcrypto ou pgsodium ne sont pas installées.' },
		'6.12' => { 'errmsg' => 'Les extensions pg_anonymize ou anon ne sont pas installées.' },
		'7.1' => { 'errmsg' => 'Un utilisateur réservé à la réplication doit être créé.' },
		'7.2' => { 'errmsg' => 'Le paramètre \'log_replication_commands\' doit être activé.' },
		'7.4' => { 'errmsg' => 'L\'archivage WAL n\'est pas activé. Le paramètre \'archive_mode\' doit être activé.' },
		'7.5' => { 'errmsg' => 'Les paramètres \'archive_command\' ou \'archive_library\' doivent être activés.' },
		'7.6' => { 'errmsg' => 'Le paramètre \'primary_conninfo\' doit appliquer le cryptage TLS de la réplication (sslmode=required).' },
		'7.7' => { 'errmsg' => 'Le paramètre \'primary_conninfo\' devrait activer la compression SSL (sslcompression=1).' },
		'8.2' => { 'errmsg' => 'L\'outil de sauvegarde \'pgBackRest\' n\'est pas installé.' },
		'8.3' => { 'errmsg' => 'Aucune strophe n\'existe pour \'pgBackRest\'.' },
	},
);

1;

