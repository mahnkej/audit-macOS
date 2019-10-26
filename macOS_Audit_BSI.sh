#!/bin/sh
#
# Author: Jens Mahnke, (<maj@je-ru.de>)
# Copyright (c) 2019 All rights reserved.

# Set these values so the script can run in color
COL_NC='\e[0m' # No Color
COL_LIGHT_GREEN='\e[1;32m'
COL_LIGHT_RED='\e[1;31m'
COL_LIGHT_BLUE='\e[1;34m'
TICK="[${COL_LIGHT_GREEN}✓${COL_NC}]"
CROSS="[${COL_LIGHT_RED}✗${COL_NC}]"
INFO="[i]"
AUDIT="[${COL_LIGHT_BLUE}Audit${COL_NC}]"
ATTENTION="[${COL_LIGHT_RED}!${COL_NC}]"

# shellcheck disable=SC2034
DONE="${COL_LIGHT_GREEN} done!${COL_NC}"
OVER="\\r\\033[K"


# Set Hardware values
HW_UUID=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Hardware UUID' | awk ' { print $3 }'`
MODELNAME=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Model Name' | awk ' { print $3 }'`
MODELIDENTIFIER=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Model Identifier' | awk ' { print $3 }'`
SERIALNUMBER=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Serial Number' | awk ' { print $4 }'`
BOOTROM=`system_profiler SPHardwareDataType 2> /dev/null | grep 'Boot ROM Version' | awk ' { print $4 }'`
OSXVERSION=`sw_vers -productVersion`
WERBINICH=`id -F "$(whoami)"`
BENUTZERID=`id -u "$(whoami)"`
product_version=$(sw_vers -productVersion)
os_vers=( ${product_version//./ } )
OS_vers_major="${os_vers[0]}"
OS_vers_minor="${os_vers[1]}"
OS_vers_patch="${os_vers[2]}"
OS_vers_build=$(sw_vers -buildVersion)


# Set date value
DATE=`date '+%Y%m%d'`

# set summary file value
Audit_folder=/private/tmp/BSI_Audit/${DATE}
Audit_file=${Audit_folder}/${SERIALNUMBER}_${DATE}.txt
evidence_folder=${Audit_folder}/evidence

# define global functions

CHECK_IF_ROOT ()
{
    if [[ $EUID -ne 0 ]]; then
		printf "  %b sudo are not used %s\\n" "${CROSS}" "This script must be run as root"
        exit 1;
    fi
}

###

AUDIT_PRE ()
{
mkdir -p -m 0777 /private/tmp/BSI_Audit
mkdir -p -m 0777 ${Audit_folder}
mkdir -p -m 0777 ${evidence_folder}
}

CLEANUP ()
{
	rm -rf ${Audit_folder}
}

###


GEN_SUMMARY_SEPARATOR()
{
    printf "  %b  %s\\n"
    printf "  %b------------------------------------------------------------------------------------------------------------%s\\n"	
	printf "  %b  %s\\n"
}

User_gt_500 ()
{
	dscl . list /Users UniqueID | awk '$2 > 500 { print $1 }' >> ${Audit_folder}/TMP_User_List_gt_500
}


User_LIST ()
{
	dscl . list /Users UniqueID | awk ' { print $1 }' > ${evidence_folder}/TMP_User_List
}

TMP_Folder_Applications ()
{
find /Applications -iname *.app -maxdepth 1 -print | sed 's/\/Applications\///g' >> ${evidence_folder}/TMP_Application
}

suported_macos ()
{
	GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
	
	if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -ge 10 ]] && [[ ${OS_vers_minor} -lt 15 ]]; then
		printf "	%b	Die aktuelle Version ${OSXVERSION} von macOS wird vom Script unterstützt %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die aktuelle Version ${OSXVERSION} von macOS wird vom Script nicht unterstützt %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Das Script wird beendet %s\\n" | tee -a ${Audit_file}
		exit
	fi
	GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
	
	sleep 1	
}

################################################### 
#
# Audit vorbereiten
#
###################################################

CLEANUP
AUDIT_PRE
User_gt_500
User_LIST
TMP_Folder_Applications
suported_macos

################################################### 
#
# Passwort für sudo erfragen
#
###################################################

sudo -v

###################################################
###################################################
#
#
# BSI - Basis-Anforderungen
#
#
###################################################
###################################################

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
printf %s "\
	Die folgenden Basis-Anforderungen MÜSSEN für die BSI IT-Grundschutz Bausteine \" SYS.2.4 Clients unter
	macOS\" und \"SYS.2.1 Allgemeiner Client\" vorrangig umgesetzt werden:" | tee -a ${Audit_file}

printf "\n\n" | tee -a ${Audit_file}
GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
#
# SYS.2.1.A1 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A1 Benutzerauthentisierung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Um den Client zu nutzen, MÜSSEN sich die Benutzer gegenüber dem IT-System authentisieren.
	Sollen die Benutzer hierfür Passwörter verwenden, MÜSSEN sichere Passwörter benutzt werden. 
	Die Passwörter MÜSSEN der Passwort-Richtlinie der Institution entsprechen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}
SYS21M1_getglobalpolicy ()
{
pwpolicy -n /Local/Default -getglobalpolicy 2> /dev/null >> ${evidence_folder}/SYS21M1_Passwort_Global_Policy
printf "	%b	Überprüfe, ob eine globale Passwort-Policy gesetzt ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(pwpolicy -n /Local/Default -getglobalpolicy | wc -l) == "0" ]; then
	printf "	%b	Es ist keine globale Passwort-Policy gesetzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Es ist eine globale Passwort-Policy gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
	pwpolicy  --get-effective-policy 2> /dev/null >> ${evidence_folder}/SYS21M1_Passwort_Effective_Policy
fi

printf "\n" | tee -a ${Audit_file}
}

SYS21M1_mdm_passwordpolicy ()
{
printf "	%b	Überprüfe, ob via Profilmanager das System ${MODELIDENTIFIER} verwaltet wird.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(system_profiler SPConfigurationProfileDataType | wc -l) -gt 0 ] ; then
	system_profiler SPConfigurationProfileDataType >> ${evidence_folder}/SYS21M1_SPConfigurationProfileDataType
	printf "	%b	Das System ${MODELIDENTIFIER} wird mittels Profilen verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob die Passwort-Einstellungen verwaltet werden. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [ $(system_profiler SPConfigurationProfileDataType | grep -c "com.apple.mobiledevice.passwordpolicy") -gt 0 ] ; then
	system_profiler SPConfigurationProfileDataType | sed -n '/com.apple.mobiledevice.passwordpolicy/,/}/p' >> ${evidence_folder}/SYS21M1_mdm_passwordpolicy
		printf "	%b	die Passwort-Einstellungen werden per MDM verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	
	
	#################################################
	# 
	# allowSimple Passwords
	#
	#################################################	
	printf "	%b	Überprüfe, ob einfache Passwörter erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep -c "allowSimple") == 1 ]] ; then
		if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowSimple"| awk ' { print $3 }') == "0;" ]] ; then
			printf "	%b	einfache Passwörter sind nicht erlaubt. %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	einfache Passwörter sind erlaubt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Die Verwendung von einfachen Passwörtern ist nicht konfiguriert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi	
	
	
	#################################################
	# 
	# requireAlphanumeric Passwords
	#
	#################################################	
	printf "	%b	Überprüfe, ob alphanumerische Werte für das Passwort gefordert sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep -c "requireAlphanumeric") == 1 ]] ; then
		if [[ $(system_profiler SPConfigurationProfileDataType | grep "requireAlphanumeric"| awk ' { print $3 }' ) == "0;" ]] ; then
			printf "	%b	alphanumerische Werte sind nicht gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	alphanumerische Werte sind gefordert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	alphanumerische Werte sind nicht gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}		
	fi		

	
	#################################################
	# 
	# minLength Passwords
	#
	#################################################	
	printf "	%b	Überprüfe, was die minimale Länge geforderte Länge eines Passwortes ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep -c "minLength") == 1 ]] ; then
		value_pwd_minLength=`system_profiler SPConfigurationProfileDataType | grep "minLength"| awk ' { print $3 }' | sed 's/;//'`
		if [[ ${value_pwd_minLength} -lt 8 ]] ; then
			printf "	%b	Es ist eine minimale Passwortlänge von kleiner 8 Zeichen gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${value_pwd_minLength} -gt 7 ]] && [[ ${value_pwd_minLength} -lt 16 ]] ; then
			printf "	%b	Es ist eine minimale Passwortlänge zwischen 8 und 15 Zeichen gefordert. %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Es wird für Administratoren eine minimale Passwortlänge zwischen 12 und 15 Zeichen empfohlen. %s\\n" | tee -a ${Audit_file}
		elif [[ ${value_pwd_minLength} -gt 15 ]] ; then
			printf "	%b	Es ist eine minimale Passwortlänge von mindestens 16 Zeichen gefordert. %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Bei dieser Länge ist mit schlechten Passwörtern für den Login Prozess zu rechnen. %s\\n" | tee -a ${Audit_file}
		fi	
	else
		printf "	%b	Es ist keine minimale Passwortlänge gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi

	
	#################################################
	# 
	# Password maxGracePeriod
	#
	#################################################	
	printf "	%b	Überprüfe, welche maximale Grace-Priod für die geforderte Passworteingabe hinterlegt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep -c "minLength") == 1 ]] ; then
		value_pwd_maxGracePeriod=`system_profiler SPConfigurationProfileDataType | grep "maxGracePeriod"| awk ' { print $3 }' | sed 's/;//'`
		if [[ ${value_pwd_maxGracePeriod} == 0 ]] ; then
			printf "	%b	Es ist keine Grace-Period erlaubt. Das Passwort muss sofort eingegeben werden. %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ ${value_pwd_maxGracePeriod} -gt 0 ]] && [[ ${value_pwd_maxGracePeriod} -lt 6 ]] ; then
			printf "	%b	Es ist eine Grace-Period zwischen 1 und 5 Minuten erlaubt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${value_pwd_maxGracePeriod} -gt 5 ]] && [[ ${value_pwd_maxGracePeriod} -lt 241 ]] ; then
			printf "	%b	Es ist eine Grace-Period zwischen 6 und 240 Minuten erlaubt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist keine Grace-Period konfiguriert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi

	
	#################################################
	# 
	# minComplexChars Passwords
	#
	#################################################	
	printf "	%b	Überprüfe die mindest Anzahl an komplexen Werte innerhalb des Passworts. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep -c "minComplexChars") == 1 ]] ; then
		if [[ $(system_profiler SPConfigurationProfileDataType | grep "minComplexChars"| awk ' { print $3 }' | sed 's/;//') == 0 ]] ; then
			printf "	%b	Es ist keine Mindestanzahl an komplexen Zeichen gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ $(system_profiler SPConfigurationProfileDataType | grep "minComplexChars"| awk ' { print $3 }' | sed 's/;//') == 1 ]] ; then
			printf "	%b	Es ist ein Zeichen mindestens gefordert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ $(system_profiler SPConfigurationProfileDataType | grep "minComplexChars"| awk ' { print $3 }' | sed 's/;//') -gt 1 ]] ; then
			printf "	%b	Es ist mehr als ein Zeichen mindestens gefordert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist keine Mindestanzahl an komplexen Zeichen gefordert. %s\\n" "${CROSS}" | tee -a ${Audit_file}		
	fi
	
		printf "\n" | tee -a ${Audit_file}
	
	else
		
		printf "	%b	die Passwort-Einstellungen werden nicht per MDM verwaltet. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	fi
else
	
	printf "	%b	Das System ${MODELIDENTIFIER} wird nicht mittels Profilen verwaltet. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
fi

printf "\n" | tee -a ${Audit_file}

}

sub_SYS21M1_gethashtypes ()
{
while read User_gt_500
do
printf "	%b 	Überprüfe für den Benutzer ${User_gt_500} , welche Hash-Algorithmen genutzt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
pwpolicy -u ${User_gt_500} -gethashtypes 2> /dev/null >> ${evidence_folder}/${User_gt_500}_USER_Hashes


	#################################################
	# 
	# Hash Integer value per algorithmen
	#
	#################################################
	while read USER_Hashes
	do
		if [ $(pwpolicy -u ${User_gt_500} -gethashtypes 2> /dev/null | grep -c ${USER_Hashes}) == 1 ]; then
			if [ $(pwpolicy -u ${User_gt_500} -gethashtypes 2> /dev/null | grep ${USER_Hashes}) == ${USER_Hashes} ]; then
				printf "	%b	Vom Benutzer ${User_gt_500}  wird der Algorithmus \"${USER_Hashes}\" genutzt. %s\\n" "${TICK}" | tee -a ${Audit_file}
				local HASH_Integer=`sudo defaults read /var/db/dslocal/nodes/Default/users/${User_gt_500}.plist ShadowHashData|tr -dc 0-9a-f|xxd -r -p | plutil -convert xml1 - -o - | sed -n '/'${USER_Hashes}'/,/salt/p' | grep "integer" | sed 's/<integer>//' | sed 's/<\/integer>//'`
				local HASH_Integer_WCL=`sudo defaults read /var/db/dslocal/nodes/Default/users/${User_gt_500}.plist ShadowHashData|tr -dc 0-9a-f|xxd -r -p | plutil -convert xml1 - -o - | sed -n '/'${USER_Hashes}'/,/salt/p' | grep "integer" | sed 's/<integer>//' | sed 's/<\/integer>//' | wc -l`
				if [ ${HASH_Integer_WCL} -gt 0 ]; then
					printf "	%b	Der Algorithmus \"${USER_Hashes}\" wird mit einem Integer-Wert von genutzt:
	${HASH_Integer} %s\\n" "${INFO}" | tee -a ${Audit_file}
				else
					printf " 		Für den Algorithmus \"${USER_Hashes}\" konnte für den Benutzer ${User_gt_500} kein Wert ermittelt werden\\n" | tee -a ${Audit_file}					
				fi
		printf "\n" | tee -a ${Audit_file}
			fi
		else
			printf "	%b	Für den Benutzer ${User_gt_500} konnten keine Algorithmen emittelt werden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	done < ${evidence_folder}/${User_gt_500}_USER_Hashes
	

	#################################################
	# 
	# local KDC algorithmen
	#
	#################################################
	printf "	%b	Überprüfe für den Benutzer: ${User_gt_500}, welcher Algorithmus für Local KDC (lokale Authentifizierung) bei
		Peer-to-Peer-Diensten verwendet wird. Insbesondere bei AFP-Filesharing, 
		Screen Sharing und Back to My Mac. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local LKDC_Value=`dscl . -read /Users/${User_gt_500} AuthenticationAuthority 2> /dev/null | awk '{split($0,a,";"); print  a[6]}' | sed 's/:/./g' | awk '{split($0,a,"."); print  a[2]}'`
		local LKDC_VALUE_WCL=`dscl . -read /Users/${User_gt_500} AuthenticationAuthority 2> /dev/null | awk '{split($0,a,";"); print  a[6]}' | sed 's/:/./g' | awk '{split($0,a,"."); print  a[2]}' | wc -l `
		if [ ${LKDC_VALUE_WCL} -gt 0 ]; then
			printf " 		Der Benutzer ${User_gt_500} nutzt für lokal KDC: "${LKDC_Value}"\\n" | tee -a ${Audit_file}
		else
			printf " 		Für den Benutzer ${User_gt_500} konnte nicht der lokale KDC-Algorithmus ermittelt werden\\n" | tee -a ${Audit_file}
			printf " 		Der Benutzer ${User_gt_500} war wahrscheinlich noch nie angemeldet am System\\n" | tee -a ${Audit_file}
		fi	
			
		printf "\n" | tee -a ${Audit_file}
			
done < ${Audit_folder}/TMP_User_List_gt_500


printf "	%b	Überprüfe, welche Hash Algorithmen für den Benutzer root aktiv sind. %s\\n" "${INFO}" | tee -a ${Audit_file}	
if [ $(dscl . -read /Users/root | grep -c "ShadowHash") != 0 ]; then
	pwpolicy -u root -gethashtypes 2> /dev/null >> ${evidence_folder}/root_USER_Hashes
while read ROOT_Hashes
	do
		if [ $(pwpolicy -u root -gethashtypes 2> /dev/null | grep -c ${ROOT_Hashes}) == 1 ]; then
			if [ $(pwpolicy -u root -gethashtypes 2> /dev/null | grep ${ROOT_Hashes}) == ${ROOT_Hashes} ]; then
				printf "	%b	Vom Benutzer root wird der Algorithmus \"${ROOT_Hashes}\" genutzt. %s\\n" | tee -a ${Audit_file}
				local HASH_Integer=`sudo defaults read /var/db/dslocal/nodes/Default/users/root.plist ShadowHashData|tr -dc 0-9a-f|xxd -r -p | plutil -convert xml1 - -o - | sed -n '/'${ROOT_Hashes}'/,/salt/p' | grep "integer" | sed 's/<integer>//' | sed 's/<\/integer>//'`
				printf "	%b	Der Algorithmus \"${ROOT_Hashes}\" wird mit einem Integer-Wert von genutzt:
	${HASH_Integer} %s\\n" "${INFO}" | tee -a ${Audit_file}
		printf "\n" | tee -a ${Audit_file}
			fi
		else
			printf "	%b	 der Benutzer root war noch nie aktiviert worden und somit keine Passwort Hashes hinterlegt. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	done < ${evidence_folder}/root_USER_Hashes

else
	printf "	%b	der Benutzer root war noch nie aktiviert worden und somit keine Passwort Hashes hinterlegt. %s\\n" "${TICK}" | tee -a ${Audit_file}
fi
}

	
	
SYS21M1_gethashtypes ()
{	
	
printf "	%b	Die folgenden aufgeführten Hash Types sollten nicht mehr verwendet werden: %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
printf "	%b		cram-md5	Required for IMAP. %s\\n" | tee -a ${Audit_file}
printf "	%b		RECOVERABLE	Required for APOP and WebDAV. Only available on Mac OS X Server edition. %s\\n" | tee -a ${Audit_file}
printf "	%b		SMB-NT		Required for compatibility with Windows NT/XP file sharing. %s\\n" | tee -a ${Audit_file}
printf "	%b		SHA1		Legacy hash for loginwindow. %s\\n" | tee -a ${Audit_file}
printf "	%b		SALTED-SHA1	Legacy hash for loginwindow. %s\\n" | tee -a ${Audit_file}
printf "	%b		SALTED-SHA512	Legacy hash for loginwindow. %s\\n" | tee -a ${Audit_file}
printf "\n" | tee -a ${Audit_file}

if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -ge 10 ]] && [[ ${OS_vers_minor} -lt 14 ]]; then

	sub_SYS21M1_gethashtypes

	else
		printf "	%b 	Überprüfe die macOS Version und ob der Pfad /var durch Systemintegritätsschutz (SIP) geschützt wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		
		SIPSTATUS=`csrutil status 2> /dev/null |  awk ' { print $5 }'`
		if [ ${SIPSTATUS} == "enabled." ]; then
			
			printf "	%b	System Integrity Protection (SIP) ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
			# ab macOs 10.14 wird mittels SIP der Zugriff auf die Pfade /System , /usr , /bin , /sbin und /var geschützt
			printf "	%b	Die Zugriffe auf die Pfade /System , /usr , /bin , /sbin und /var sind durch SIP unter macOS ${OSXVERSION} Build-Nummer ${OS_vers_build} geschützt. %s\\n" "${TICK}"
			printf "	%b	Es kann nicht überprüft werden, welche Hash Algorithmen für den Benutzer root aktiv sind. %s\\n" "${INFO}" | tee -a ${Audit_file}
			while read User_gt_500
				do
					printf "	%b	Es kann nicht überprüft werden, welche Hash Algorithmen für den Benutzer ${User_gt_500} aktiv sind. %s\\n" "${INFO}" | tee -a ${Audit_file}
				done < ${Audit_folder}/TMP_User_List_gt_500
			
		else
			printf "	%b	System Integrity Protection (SIP) ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
			printf "	%b	Die Zugriffe auf den Pfad /System , /usr , /bin , /sbin und /var sind durch SIP nicht geschützt. %s\\n" "${CROSS}"
			
			sub_SYS21M1_gethashtypes
			
		fi
		
fi

printf "\n" | tee -a ${Audit_file}

}

SYS21M1_getglobalpolicy
sleep 0.5
SYS21M1_mdm_passwordpolicy
sleep 0.5
SYS21M1_gethashtypes
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
#
# SYS.2.1.A2 BSI
#
###################################################

printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A2 Rollentrennung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Der Client MUSS so eingerichtet werden, dass normale Tätigkeiten nicht mit Administrationsrechten erfolgen. 
	Nur Administratoren DÜRFEN Administrationsrechte erhalten. Es DÜRFEN nur Administratoren die Systemkonfiguration 
	ändern, Anwendungen installieren bzw. entfernen oder Systemdateien modifizieren bzw. löschen können. Benutzer 
	DÜRFEN ausschließlich lesenden Zugriff auf Systemdateien haben.

	Ablauf, Rahmenbedingungen und Anforderungen an administrative Aufgaben sowie die Aufgabentrennungen zwischen 
	den verschiedenen Rollen der Benutzer des IT-Systems SOLLTEN in einem Benutzer- und Administrationskonzept 
	festgeschrieben werden." | tee -a ${Audit_file}

	printf "\n\n" | tee -a ${Audit_file}
	
###################################################
# 
# SYS.2.1.M2 Benutzer mit der ID 0
#
###################################################

SYS21M2_USERID_ROOT ()
{
printf "	%b	Auflistung der Konten, die als Benutzer mit der ID 0 hinterlegt sind. %s\\n" "${INFO}" | tee -a ${Audit_file}
ROOTMEMBER=`dscl . list /Users UniqueID | awk '$2 == 0 { print $1 }'` 
dscl . list /Users UniqueID >> ${evidence_folder}/SYS21M2_User_List

printf " 		Folgende Benutzer sind mit der ID 0 hinterlegt: "${ROOTMEMBER}"\\n" | tee -a ${Audit_file}
printf "\n" | tee -a ${Audit_file}

}


###################################################
# 
# SYS.2.1.M2 Benutzer der Gruppe wheel
#
###################################################

SYS21M2_MEMBER_WHEEL ()
{

printf "	%b	Auflistung der Konten mit Systemrechten: %s\\n" "${INFO}" | tee -a ${Audit_file}

while read WHEEL_Member
	do
		if [[ $(dsmemberutil checkmembership -U "${WHEEL_Member}" -G wheel) == "user is a member of the group" ]]; then
		printf " 		der Benutzer \""${WHEEL_Member}"\" ist Mitglied der Gruppe wheel und besitzt administrative Systemrechte. \\n" | tee -a ${Audit_file}
    	fi
		
	done < ${evidence_folder}/TMP_User_List
	
	printf "\n" | tee -a ${Audit_file}

}


###################################################
# 
# SYS.2.1.M2 Benutzer der Gruppe admin
#
###################################################


SYS21M2_MEMBER_ADMIN ()
{
printf "	%b	Auflistung der Konten mit administrativen Rechten: %s\\n" "${INFO}" | tee -a ${Audit_file}

while read ADMIN_Member
	do
		if [[ $(dsmemberutil checkmembership -U "${ADMIN_Member}" -G admin) == "user is a member of the group" ]]; then
		printf " 		der Benutzer \""${ADMIN_Member}"\" ist Mitglied der Gruppe admin. \\n" | tee -a ${Audit_file}
    	fi
		
	done < ${evidence_folder}/TMP_User_List
	
printf "\n" | tee -a ${Audit_file}
}


###################################################
# 
# SYS.2.1.M2 Benutzer mit UID > 500
#
###################################################

SYS21M2_USER_GREATER500 ()
{
printf "	%b	Auflistung der Konten mit UID größer 500: %s\\n" "${INFO}" | tee -a ${Audit_file}
dscl . list /Users UniqueID | awk '$2 > 500 { print $1 }' >> ${evidence_folder}/SYS21M2_User_List_gt_500

while read USER_gt_500
	do
		printf "  %b 		Das Benutzerkonto \""${USER_gt_500}"\" hat eine ID größer 500 %s\\n" | tee -a ${Audit_file}
	done < ${evidence_folder}/SYS21M2_User_List_gt_500
	
printf "\n\n" | tee -a ${Audit_file}
}


###################################################
# 
# SYS.2.1.M2 Gast Account
#
###################################################

SYS21M2_USER_GUEST ()
{
printf "	%b	Überprüfe, ob das Gastkonto aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}

GASTKONTO=`defaults read /Library/Preferences/com.apple.loginwindow.plist | grep "GuestEnabled" | awk ' { print $3 }'`

if [ ${GASTKONTO} == "0;" ]; then
	printf "	%b	Gastkonto ist nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Gastkonto ist aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
		printf "\n" | tee -a ${Audit_file}
}

SYS21M2_USERID_ROOT
sleep 0.5
SYS21M2_MEMBER_WHEEL
sleep 0.5
SYS21M2_MEMBER_ADMIN
sleep 0.5
SYS21M2_USER_GREATER500
sleep 0.5
SYS21M2_USER_GUEST
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
# 
# SYS.2.1.A3 BSI
#
###################################################

printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A3 Aktivieren von Autoupdate-Mechanismen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Automatische Update-Mechanismen (Autoupdate) MÜSSEN aktiviert werden, sofern nicht andere Mechanismen 
	wie regelmäßige manuelle Wartung oder ein zentrales Softwareverteilungssystem für Updates eingesetzt 
	werden. Wenn für Autoupdate-Mechanismen ein Zeitintervall vorgegeben werden kann, SOLLTE mindestens 
	täglich automatisch nach Updates gesucht und diese installiert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}


SYS21M3 ()
{
	local SW_Update_Search=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "AutomaticCheckEnabled" | awk ' { print $3 }'`
	local SW_Auto_Download_WC=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "AutomaticDownload" | wc -l`
	local SW_Auto_Download=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "AutomaticDownload" | awk ' { print $3 }'`
	local SW_Auto_ConfigDataInstall_WC=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "ConfigDataInstall" | wc -l`
	local SW_Auto_ConfigDataInstall=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "ConfigDataInstall" | awk ' { print $3 }'`
	local SW_Auto_CriticalUpdateInstall_WC=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "CriticalUpdateInstall" | wc -l`
	local SW_Auto_CriticalUpdateInstall=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "CriticalUpdateInstall" | awk ' { print $3 }'`
	local SW_LastUpdatesAvailable=`defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | grep "LastUpdatesAvailable" | awk ' { print $3 }'`
		
	printf "	%b	Überprüfe, ob automatisch nach Updates im App-Store gesucht wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
	defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist 2> /dev/null >> ${evidence_folder}/SYS21M3_Softwareupdate
	if [[ ${SW_Update_Search} == "1;" ]]; then
			printf "	%b	die automatische Suche nach Updates im App-Store ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	die automatische Suche nach Updates im App-Store ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
	
	printf "	%b	Überprüfe, ob Updates automatisch heruntergeladen werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_Download_WC} == "0" ]]; then
		printf "	%b	Updates werden automatisch heruntergeladen %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_Download} == "1;" ]]; then
		printf "	%b	Updates werden automatisch heruntergeladen %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	Updates werden nicht automatisch heruntergeladen %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "0;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	Updates werden nicht automatisch heruntergeladen %s\\n" "${CROSS}" | tee -a ${Audit_file}
	else
		printf "	%b	Bitte die Einstellungen in den Preferences unter App Store überprüfen. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
	fi

	printf "	%b	Überprüfe, ob Systemupdates automatisch installiert werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_ConfigDataInstall_WC} == "0" ]]; then
		printf "	%b	Systemupdates werden automatisch installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_ConfigDataInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "1;" ]]; then
		printf "	%b	Systemupdates werden automatisch installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_ConfigDataInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	Auf Grund fehlendem automatischen Download werden Systemupdates nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_ConfigDataInstall} == "0;" ]] && [[ ${SW_Auto_Download} == "1;" ]]; then
		printf "	%b	Systemupdates werden nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_ConfigDataInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	Systemupdates werden nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "0;" ]] && [[ ${SW_Auto_ConfigDataInstall} == "1;" ]]; then
		printf "	%b	Auf Grund fehlender automatischen Suche und Download werden Systemupdates nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	else
		printf "	%b	Bitte die Einstellungen in den Preferences unter App Store überprüfen. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
	fi
	
	printf "	%b	Überprüfe, ob kritische Updates automatisch installiert werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_CriticalUpdateInstall_WC} == "0" ]]; then
		printf "	%b	kritische Updates werden automatisch installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_CriticalUpdateInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "1;" ]]; then
		printf "	%b	kritische Updates werden automatisch installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_CriticalUpdateInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	Auf Grund fehlendem automatischen Download werden kritische Updates nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_CriticalUpdateInstall} == "0;" ]] && [[ ${SW_Auto_Download} == "1;" ]]; then
		printf "	%b	kritische Updates werden nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_Auto_CriticalUpdateInstall} == "1;" ]] && [[ ${SW_Auto_Download} == "0;" ]]; then
		printf "	%b	kritische Updates werden nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "0;" ]] && [[ ${SW_Auto_CriticalUpdateInstall} == "1;" ]]; then
		printf "	%b	Auf Grund fehlender automatischen Suche und Download werden kritische Updates nicht automatisch installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	else
		printf "	%b	Bitte die Einstellungen in den Preferences unter App Store überprüfen. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
	fi
	
	printf "	%b	Überprüfe, wie viele Updates aktuell noch nicht installiert wurden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_LastUpdatesAvailable} == "0;" ]]; then
		printf "	%b	es sind alle von Apple bereitgestellten Updates installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "1;" ]] && [[ ${SW_LastUpdatesAvailable} != "0;" ]]; then
		printf "	%b	es sind nicht alle von Apple bereitgestellten Updates installiert worden %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "0;" ]] && [[ ${SW_LastUpdatesAvailable} == "0;" ]]; then
		printf "	%b	Auf Grund fehlender automatischen Suche sind wahrscheinlich nicht alle von Apple bereitgestellten Updates installiert worden %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Überprüfe direkt, wie viele Updates aktuell noch nicht installiert wurden. %s\\n" "${INFO}" | tee -a ${Audit_file}
		softwareupdate -l | tee -a ${Audit_file}
	elif [[ ${SW_Update_Search} == "0;" ]] && [[ ${SW_LastUpdatesAvailable} != "0;" ]]; then
		printf "	%b	Auf Grund fehlender automatischen Suche sind wahrscheinlich nicht alle von Apple bereitgestellten Updates installiert worden %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Überprüfe direkt, wie viele Updates aktuell noch nicht installiert wurden. %s\\n" "${INFO}" | tee -a ${Audit_file}
		softwareupdate -l | tee -a ${Audit_file}
	fi
}	
	
SYS21M3
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
# 
# SYS.2.1.A4 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A4 Regelmäßige Datensicherung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Zur Vermeidung von Datenverlusten MÜSSEN regelmäßige Datensicherungen erstellt werden. In den
	meisten Rechnersystemen können diese weitgehend automatisiert erfolgen. Es MÜSSEN Regelungen 
	getroffen werden, welche lokal abgespeicherten Daten von wem wann gesichert werden. Es MÜSSEN 
	mindestens die Daten regelmäßig gesichert werden, die nicht aus anderen Informationen abgeleitet 
	werden können. Auch Clients MÜSSEN in das Datensicherungskonzept der Institution einbezogen werden. 
	Bei vertraulichen und ausgelagerten Backups SOLLTEN die gesicherten Daten verschlüsselt gespeichert 
	werden. Für eingesetzte Software SOLLTE separat entschieden werden, ob sie von der regelmäßigen 
	Datensicherung erfasst werden muss. Es MUSS regelmäßig getestet werden, ob die Datensicherung auch 
	wie gewünscht funktioniert, vor allem, ob gesicherte Daten problemlos zurückgespielt werden können. 
	Die Benutzer SOLLTEN über die Regelungen, von wem und wie Datensicherungen erstellt werden, 
	informiert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M4 ()
{
	printf "	%b	Überprüfe, ob bekannte Backup-Programme im Ordner Applications erkant werden. %s\\n" "${INFO}" | tee -a ${Audit_file}	
printf " 		Im Ordner Applications wurde die folgende bekannte Anwendung gefunden: \n" | tee -a ${Audit_file}
	if [[ $(grep -c "Time Machine.app" ${evidence_folder}/TMP_Application) == "1" ]]; then
			printf " 		Time Machine  \n" | tee -a ${Audit_file}
	fi
	
	if [[ $(grep -c "SuperDuper!.app" ${evidence_folder}/TMP_Application) == "1" ]]; then
			printf " 		SuperDuper!  \n" | tee -a ${Audit_file}
	fi
	
	if [[ $(grep -c "SuperDuper!.app" ${evidence_folder}/TMP_Application) == "0" ]] && [[ $(grep -c "Time Machine.app" ${evidence_folder}/TMP_Application) == "0" ]] ; then
			printf " 		Es wurde keine bekannte Backup-Anwendung im Ordner Applications gefunden.   \n" | tee -a ${Audit_file}
	fi	
	
local TM_AutoBackup=`defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep "AutoBackup" | awk ' { print $3 }'`


printf "	%b	Überprüfe, ob regelmäßig Datensicherungen mittels Timemachine durchgeführt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [[ ${TM_AutoBackup} == "1;" ]]; then
	defaults read /Library/Preferences/com.apple.TimeMachine.plist >> ${evidence_folder}/SYS21M4_Timemachine_settings
	defaults read /System/Library/LaunchDaemons/com.apple.backupd-helper.plist >> ${evidence_folder}/SYS21M4_Timemachine_backupd_helper
	defaults read /Library/Preferences/com.apple.TimeMachine.plist | sed -n '/SnapshotDates/,/);/p' | tr 'SnapshotDates =             ( ' ' ' |  tr '); ' ' ' >> ${evidence_folder}/SYS21M4_Timemachine_history
	tmutil machinedirectory >> ${evidence_folder}/SYS21M4_Timemachine_machinedirectory
	tmutil destinationinfo >> ${evidence_folder}/SYS21M4_Timemachine_destinationinfo
		
	local TM_AlwaysShowDeletedBackupsWarning=`defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep "AlwaysShowDeletedBackupsWarning" | awk ' { print $3 }'`
	local TM_LastKnownEncryptionState=`defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep "LastKnownEncryptionState" | awk ' { print $3 }'`
	local TM_DateOfLatestWarning=`defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep "DateOfLatestWarning" | awk ' { print $3 " " $4}' | tr '" ' ' '`
	local TM_Version=`tmutil version | awk ' { print $0}'`
	local TM_GracePeriod=`defaults read /System/Library/LaunchDaemons/com.apple.backupd-helper.plist | grep "GracePeriod" | awk ' { print $3}' | tr '; ' ' '`
	local TM_Interval=`defaults read /System/Library/LaunchDaemons/com.apple.backupd-helper.plist | grep "Interval" | awk ' { print $3}' | tr '; ' ' '`
	local TM_Delay=`defaults read /System/Library/LaunchDaemons/com.apple.backupd-helper.plist | grep "Delay" | awk ' { print $3}' | tr '; ' ' '`
	local TM_Dir_local=`tmutil machinedirectory | awk ' { print $0}'`
	local TM_Dir_Name=`tmutil destinationinfo | grep "Name" | awk ' { print $3}'`
	local TM_Dir_Kind=`tmutil destinationinfo | grep "Kind" | awk ' { print $3}'`
	local TM_Dir_ID=`tmutil destinationinfo | grep "ID" | awk ' { print $3}'`
		
		
	printf "	%b	Es werden regelmäßig Backups mittels Timemachine durchgeführt. %s\\n" "${TICK}" | tee -a ${Audit_file}
		
	printf "	%b	Überprüfe, welche Version von Timemachine verwendet wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Es wird ${TM_Version} eingesetzt. \n" | tee -a ${Audit_file}
		
	printf "	%b	Überprüfe, welche Grace Period von Timemachine verwendet wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Es ist eine Grace Period von ${TM_GracePeriod} Sekunden konfiguriert. \n" | tee -a ${Audit_file}
		
	printf "	%b	Überprüfe, welches Interval für Timemachine gesetzt ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Es ist ein Interval von ${TM_Interval} Sekunden gesetzt. \n" | tee -a ${Audit_file}
		
	printf "	%b	Überprüfe, welches Delay für Timemachine gesetzt ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Es ist ein Delay von ${TM_Delay} Sekunden gesetzt. \n" | tee -a ${Audit_file}
		
	printf "	%b	Überprüfe, wann Backups erstellt wurden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	while read TM_History
	do
		printf " 		${TM_History} \n" | tee -a ${Audit_file}	
	done < ${evidence_folder}/SYS21M4_Timemachine_history
		
	printf "	%b	Ermittele das lokale Timemachine Directory für die lokale Zwischenspeicherung. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Timemachine verwendet lokal das Verzeichnis ${TM_Dir_local} . \n" | tee -a ${Audit_file}
		
	printf "	%b	Ermittele das Timemachine Directory für die Speicherung von Backups. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "		Name: "${TM_Dir_Name}" \\n" | tee -a ${Audit_file}
	printf "		Art der Speicherung: "${TM_Dir_Kind}" \\n" | tee -a ${Audit_file}
	printf "		Timemachine ID: "${TM_Dir_ID}" \\n" | tee -a ${Audit_file}
		
	tmutil destinationinfo >> ${evidence_folder}/SYS21M4_tmutil_destinationinfo
	printf "	%b	 Die Zieladressen für Timemachine sind in der Datei SYS21M4_tmutil_destinationinfo im Pfad
		${evidence_folder}/SYS21M4_tmutil_destinationinfo zufinden. %s\\n"  | tee -a ${Audit_file}	

		
	printf "	%b	Überprüfe, ob die Benachrichtigung nach dem Löschen von Backups aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [[ ${TM_AlwaysShowDeletedBackupsWarning} == "0;" ]]; then
			printf "	%b	Der Benutzer wird nicht benachrichtigt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${TM_AlwaysShowDeletedBackupsWarning} == "1;" ]]; then
			printf "	%b	Der Benutzer wird  benachrichtigt. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
		
	printf "	%b	Überprüfe, ob die Backups verschlüsselt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [[ ${TM_LastKnownEncryptionState} == "NotEncrypted;" ]]; then
			printf "	%b	Die Timemachinebackups sind nicht verschlüsselt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Die Timemachinebackups sind verschlüsselt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
	printf "	%b	Überprüfe, wann es das letztemal Problme bei der Erstellung des Backups gab. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf " 		Die letze Warnung wegen einem Problem mit dem Backup erfolgte am${TM_DateOfLatestWarning} \n" | tee -a ${Audit_file}
	
	local log_filter='processImagePath contains "backupd" and subsystem beginswith "com.apple.TimeMachine"'
	local log_search_start="$(date -j -v-24H +'%Y-%m-%d %H:%M:%S')"
	printf "	%b	Überprüfe, die Logeinträge der letzten 24 Stunden vom Prozess backupd und und allen Prozessen von Timemachine.
		das Log wird in einer separaten Datei abgespeichert.	%s\\n" "${INFO}" | tee -a ${Audit_file}
	
		printf "		Einträge aus dem Log-History beginnen ab dem ${log_search_start}‚ \\n" >> ${evidence_folder}/SYS21M4_Timemachine_syslog_history
		log show --style syslog --info --start "$log_search_start" --predicate "$log_filter" >> ${evidence_folder}/SYS21M4_Timemachine_syslog_history
		printf "	%b	Die Einträge der letzten 24 Stunden sind in die Datei:
			\"${evidence_folder}/SYS21M4_Timemachine_syslog_history\" geschrieben.
		das Log wird in einer separaten Datei abgespeichert.	%s\\n" "${INFO}" | tee -a ${Audit_file}
	else
		printf "	%b	es werden aktuell keine Backups mittels Timemachine, Super Duper oder Carbon Copy Cloner durchgeführt %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi

}

SYS21M4
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
# 
# SYS.2.1.A5 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A5 Bildschirmsperre %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Eine Bildschirmsperre MUSS verwendet werden, damit keine Unbefugten auf die aktivierten Clients zugreifen 
	können. Sie SOLLTE sich sowohl manuell vom Benutzer aktivieren lassen als auch nach einem vorgegebenen 
	Inaktivitäts-Zeitraum automatisch gestartet werden. Es MUSS sichergestellt sein, dass die Bildschirmsperre 
	erst nach einer erfolgreichen Benutzerauthentikation deaktiviert werden kann.." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M5 ()

{
if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -ge 10 ]] && [[ ${OS_vers_minor} -lt 14 ]]; then
	
	while read User_List_gt_500
		do
		
			####################################################
			# 
			# SYS.2.1.M5 BSI - askForPassword default 0 (off)
			#
			###################################################
		printf "	%b	Überprüfe, ob für den Benutzer ${User_List_gt_500} im primären Pfad die Bildschirmsperre mit Passwortabfrage aktiviert ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist ]]; then
			
			defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null >> ${evidence_folder}/SYS21M5_Bildschirmsperre
			local SCREENSAVER_askForPassword_1=`defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep "askForPassword" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
			
			if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep -c "askForPassword") != 0 ]]; then
				printf "	%b	Die Bildschirmsperre mit Passwortabfrage ist für den Benutzer ${User_List_gt_500} im primären Pfad konfiguriert und aktiviert.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Die Bildschirmsperre mit Passwortabfrage ist für den Benutzer ${User_List_gt_500} im primären Pfad nicht konfiguriert. 
		Dieses ist der factory default Wert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
		
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist ]]; then
			local SCREENSAVER_askForPassword_2=`defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null | grep "askForPassword" | awk '$2 > 500 { print $3 }' |tr ';' ' '`	
			defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null >> ${evidence_folder}/SYS21M5_Bildschirmsperre
			
			printf "	%b	Überprüfe, ob für den Benutzer ${User_List_gt_500} im sekundären Pfad die Bildschirmsperre mit Passwortabfrage aktiviert ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null | grep -c "askForPassword") != 0 ]]; then
				printf " 	%b	Die Bildschirmsperre mit Passwortabfrage ist für den Benutzer ${User_List_gt_500} im sekundären Pfad konfiguriert und aktiviert.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf " 	%b	Die Bildschirmsperre mit Passwortabfrage ist für den Benutzer ${User_List_gt_500} im sekundären Pfad nicht konfiguriert. 
		Dieses ist der factory default Wert.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi	
		
			####################################################
			# 
			# SYS.2.1.M5 BSI - askForPasswordDelay default is 5 value 2147483647 means off
			#
			###################################################
		
		printf "	%b	Überprüfe im primären Pfad, ab wann die Eingabe eines Passwortes für den Benutzer: ${User_List_gt_500} nach aktiver Bildschirmsperre erforderlich ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_askForPasswordDelay_1=`defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep "askForPasswordDelay" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
		
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist ]] && [[ ${SCREENSAVER_askForPassword_1} == 1 ]]; then
			if [[ ${SCREENSAVER_askForPasswordDelay_1} != 0 ]] && [[ ${SCREENSAVER_askForPasswordDelay_1} -lt 2147483647 ]]; then
				printf "  	%b	Es wird nach ${SCREENSAVER_askForPasswordDelay_1} Minuten nach einem Passwort gefragt (dieser Wert wurde konfiguriert).  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "  	%b	Es wird sofort nach einem Passwort gefragt. %s\\n" "${TICK}"| tee -a ${Audit_file}
			fi
		else
			printf "	%b	Es würde nach 5 Minuten nach einem Passwort gefragt werden. Dieser Wert ist der factory default Wert, jedoch ist die 
		Bildschirmsperre mit Passwortabfrage nicht aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
		printf "	%b	Überprüfe im sekundären Pfad, ab wann die Eingabe eines Passwortes für den Benutzer: ${User_List_gt_500} nach aktiver Bildschirmsperre erforderlich ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_askForPasswordDelay_2=`defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null  | grep "askForPasswordDelay" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
		
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist ]] && [[ ${SCREENSAVER_askForPassword_2} == 1 ]]; then
			if [[ ${SCREENSAVER_askForPasswordDelay_2} != 0 ]] && [[ ${SCREENSAVER_askForPasswordDelay_2} -lt 2147483647 ]]; then
				printf "  	%b	Es wird nach ${SCREENSAVER_askForPasswordDelay_2} Minuten nach einem Passwort gefragt (dieser Wert wurde konfiguriert).  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "  	%b	Es wird sofort nach einem Passwort gefragt. %s\\n" "${TICK}"| tee -a ${Audit_file}
			fi
		else
			printf "	%b	Es würde nach 5 Minuten nach einem Passwort gefragt werden. Dieser Wert ist der factory default Wert, jedoch ist die 
		Bildschirmsperre mit Passwortabfrage nicht aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
			####################################################
			# 
			# SYS.2.1.M5 BSI
			#
			# loginWindowIdleTime
			# Login Window Screen Saver Idle Time
			# Idle time in seconds. Default is 20 minutes (1200 seonds). Set to 0 to disable screensaver.
			###################################################
		
		printf "	%b	Überprüfe im primären Pfad, ab wann die Bildschirmsperre für den Benutzer: ${User_List_gt_500} aktiviert wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_loginWindowIdleTime_1=`defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep "loginWindowIdleTime" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist ]] && [[ ${SCREENSAVER_askForPasswordDelay_1} == 1 ]] ; then
			if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep -c "loginWindowIdleTime") != 0 ]]; then
				printf "	%b	Die Bildschirmsperre wird aktiv nach ${SCREENSAVER_loginWindowIdleTime_1} Sekunden.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Es ist kein Wert für die Aktivierung der Bildschirmsperre bei Inaktivität für den Benutzer ${User_List_gt_500} im primären Pfad konfiguriert. 
		Der factory default Wert sind 20 Minuten. %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		else
			printf "	%b	Die Bildschirmsperre ist für den Benutzer ${User_List_gt_500} im primären Pfad nicht konfiguriert somit greift der factory default Wert von 20 Minuten nicht. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
		printf "	%b	Überprüfe im sekundären Pfad, ab wann die Bildschirmsperre für den Benutzer: ${User_List_gt_500} aktiviert wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_loginWindowIdleTime_2=`defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null  | grep "loginWindowIdleTime" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
		
		if [[ -e /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist ]] && [[ ${SCREENSAVER_askForPasswordDelay_2} == 1 ]]; then
			if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep -c "askForPasswordDelay") != 0 ]]; then
				printf "  	%b	Die Bildschirmsperre wird aktiv nach ${SCREENSAVER_loginWindowIdleTime_2} Sekunden.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "  	%b	Es ist kein Wert für die Aktivierung der Bildschirmsperre bei Inaktivität für den Benutzer ${User_List_gt_500} im sekundären Pfad konfiguriert. 
				Der factory default Wert sind 20 Minuten. %s\\n" "${TICK}"| tee -a ${Audit_file}
			fi
		else
			printf "	%b	Die Bildschirmsperre ist für den Benutzer ${User_List_gt_500} im sekundären Pfad nicht konfiguriert somit greift der factory default Wert von 20 Minuten nicht. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi			

			####################################################
			# 
			# SYS.2.1.M5 BSI 
			#
			# idleTime
			# Screen Saver Idle Time
			# Idle time in seconds. Default is 5 minutes (300 seonds). Set to 0 to disable screensaver.
			###################################################
			
			
		printf "	%b	Überprüfe im primären Pfad, ab wann der Bildschirmschoner für den Benutzer: ${User_List_gt_500} aktiviert wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_idleTime_1=`defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep "idleTime" | awk '$2 > 500 { print $3 }' |tr ';' ' '`	
		if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/com.apple.screensaver.plist 2> /dev/null | grep -c "idleTime") != 0 ]]; then
			if [[ ${SCREENSAVER_idleTime_1} != 0 ]]; then
				printf "	%b	Der Bildschirmschoner wird aktiv nach ${SCREENSAVER_idleTime_1} Sekunden.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Der Bildschirmschoner wurde deaktiviert.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		else
			printf "	%b	Es wurde kein konfigurierter Wert gefunden.  %s\\n" | tee -a ${Audit_file}
		fi
		
		printf "	%b	Überprüfe im sekundären Pfad, ab wann der Bildschirmschoner für den Benutzer: ${User_List_gt_500} aktiviert wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local SCREENSAVER_idleTime_2=`defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null  | grep "idleTime" | awk '$2 > 500 { print $3 }' |tr ';' ' '`
		if [[ $(defaults read /Users/${User_List_gt_500}/Library/Preferences/ByHost/com.apple.screensaver.${HW_UUID}.plist 2> /dev/null | grep -c "idleTime") != 0 ]]; then
			if [[ ${SCREENSAVER_idleTime_2} != 0 ]]; then
				printf "	%b	Der Bildschirmschoner wird aktiv nach ${SCREENSAVER_idleTime_2} Sekunden.  %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Der Bildschirmschoner wurde deaktiviert.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		else
			printf "	%b	Es wurde kein konfigurierter Wert gefunden.  %s\\n" | tee -a ${Audit_file}
		fi
	
		printf "\n"| tee -a ${Audit_file}
		
		
		done < ${Audit_folder}/TMP_User_List_gt_500
		
elif [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -eq 14 ]] && [[ ${OS_vers_patch} -ge 3 ]]; then
	printf "	%b Die Version ${OS_vers_major}.${OS_vers_minor}.${OS_vers_patch} ist derzeit nicht unterstützt %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
fi	
printf "\n" | tee -a ${Audit_file}
}

SYS21M5
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


##################################################
# 
# SYS.2.1.A6 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A6 Einsatz von Viren-Schutzprogrammen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	In Abhängigkeit vom installierten Betriebssystem und andere vorhandenen Schutzmechanismen des Clients 
	MUSS geprüft werden, ob Viren-Schutzprogramme eingesetzt werden sollen. Konkrete Aussagen, ob
	Viren-Schutz notwendig ist, sind in der Regel in den Betriebssystem-Bausteinen des IT-Grundschutzes 
	zu finden. Die entsprechenden Signaturen eines Viren-Schutzprogrammes MÜSSEN regelmäßig aktualisiert 
	werden. Neben Echtzeit- und On-Demand-Scans MUSS eine eingesetzte Lösung die Möglichkeit bieten, auch 
	komprimierte Daten nach Schadprogrammen zu durchsuchen.

	Viren-Schutzprogramme auf den Clients MÜSSEN so konfiguriert sein, dass die Benutzer weder 
	sicherheitsrelevante Änderungen an den Einstellungen vornehmen können noch sie deaktivieren können." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M6 ()

{
	printf "	%b	Bitte geben Sie die relevanten Anforderungen an das Auditteam weiter. Auf Grund der 
	verschiedenen Hersteller und deren spezifischen Programmeigenschaften erfolgt hier keine technische Überprüfung.	%s\\n" "${ATTENTION}" | tee -a ${Audit_file}
}

SYS21M6
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

##################################################
# 
# SYS.2.1.A7 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A7 Protokollierung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es MUSS entschieden werden, welche Informationen auf Clients mindestens protokolliert werden sollen, wie 
	lange die Protokolldaten aufbewahrt werden und wer unter welchen Voraussetzungen die Protokolldaten 
	einsehen darf. Generell MÜSSEN alle sicherheitsrelevanten Systemereignisse protokolliert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M7 ()

{
	
cat /etc/syslog.conf >> ${evidence_folder}/SYS21M7_syslog_conf
defaults read /System/Library/LaunchDaemons/com.apple.syslogd.plist >> ${evidence_folder}/SYS21M7_syslogd_plist
cat /etc/asl.conf >> ${evidence_folder}/SYS21M7_asl_conf
defaults read /System/Library/LaunchDaemons/com.apple.newsyslog.plist >> ${evidence_folder}/SYS21M7_newsyslog_plist
#ls /Library/Preferences/Logging/Subsystems/

printf "	%b	überprüfe, welche globalen Einstellungen für das Logging aktiv sind.  %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	In der Konfiguration für den Syslog Dienst ist folgendes hinterlegt:  %s\\n" "${INFO}" | tee -a ${Audit_file}
while read SYSLOGCONF
	do
		printf "	%b	${SYSLOGCONF} %s\\n" | tee -a ${Audit_file}		
	
	printf "\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M7_syslog_conf

if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ]; then
		printf "	%b	Es ist lokales Logging in der Datei syslog.conf aktiviert. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es ist kein lokales Logging in der Datei syslog.conf aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ] &&  [ $(cat /etc/syslog.conf | grep -v "@127.0.0.1" | grep -c "@") != 0 ]; then
		printf "	%b	Es ist zentrales Logging in der Datei syslog.conf aktiviert. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es ist kein zentrales Logging in der Datei syslog.conf aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi


printf "	%b	überprüfe, ob der Dienst Apple System Log für das Logging aktiv ist.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ]; then
		printf "	%b	Es wird der Apple System Log Dienst verwendet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es wird der Apple System Log Dienst nicht verwendet. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	überprüfe, welche installierten Anwendungen eine spezielle ASL Konfiguration besitzen.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(ls /etc/asl/ | wc -l) -gt 0 ]; then
		printf "	%b	Nicht alle installierten Anwendungen verwenden die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
		ls /etc/asl/ >> ${evidence_folder}/SYS21M7_Apps_dont_use_default_ASL_config
		printf "	%b	Diese Anwendungen verwenden nicht die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
		while read dont_use_default_ASL_config
			do
				printf "	%b		${dont_use_default_ASL_config} %s\\n" | tee -a ${Audit_file}
				sudo cat /etc/asl/${dont_use_default_ASL_config} >> ${evidence_folder}/SYS21M7_${dont_use_default_ASL_config}	
			done < ${evidence_folder}/SYS21M7_Apps_dont_use_default_ASL_config
	else
		printf "	%b	Alle installierten Anwendungen verwenden die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
	fi
printf "\n"| tee -a ${Audit_file}


printf "	%b	Überprüfe den Inhalt vom Pfad /var/log/.  %s\\n" "${INFO}" | tee -a ${Audit_file}
local VAR_LOG_COUNT=`ls /var/log/ | wc -l`
if [ ${VAR_LOG_COUNT} -gt 0 ]; then
		printf "	%b	Im Pfad /var/log/ befinden sich folgende Unterordner oder Dateien: %s\\n"  | tee -a ${Audit_file}
		ls /var/log/ >> ${evidence_folder}/SYS21M7_var_log_entries
		printf "	%b	Die Inhalte der Dateien bzw. Ordner müssen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read var_log_entries
			do
				printf "	%b		${var_log_entries} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M7_var_log_entries
	else
		printf "	%b	Im Pfad /var/log/ befinden sich keine Unterordner oder Dateien. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	Überprüfe den Inhalt vom Pfad /var/log/asl/ und /var/log/asl/logs.  %s\\n" "${INFO}" | tee -a ${Audit_file}
local VAR_LOG_ASL_COUNT=`ls /var/log/ | wc -l`
if [ ${VAR_LOG_ASL_COUNT} -gt 0 ]; then
		printf "	%b	Im Pfad /var/log/asl befinden sich folgende Unterordner oder Dateien: %s\\n"  | tee -a ${Audit_file}
		ls /var/log/asl >> ${evidence_folder}/SYS21M7_var_log_asl_entries
		ls /var/log/asl/logs >> ${evidence_folder}/SYS21M7_var_log_asl_entries
		printf "	%b	Die Inhalte der Dateien bzw. Ordner müssen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read var_log_asl_entries
			do
				printf "	%b		${var_log_asl_entries} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M7_var_log_asl_entries
	else
		printf "	%b	Im Pfad /var/log/ befinden sich keine Unterordner oder Dateien. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	überprüfe, ob alle installierten Anwendungen den Unified Logging Service verwenden.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(ls /Library/Logs/ | wc -l) -gt 0 ]; then
		printf "	%b	Nicht alle installierten Anwendungen verwenden den Unified Logging Service. %s\\n"  | tee -a ${Audit_file}
		ls /Library/Logs/ >> ${evidence_folder}/SYS21M7_Apps_dont_use_Unified_Logging
		printf "	%b	Für nachfolgend aufgeführten Anwendungen müssen die Logging-Einstellungen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read dont_use_Unified_Logging
			do
				printf "	%b		${dont_use_Unified_Logging} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M7_Apps_dont_use_Unified_Logging
	else
		printf "	%b	Alle installierten Anwendungen verwenden den Unified Logging Service. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

while read User_List_gt_500
	do
		printf "	%b	überprüfe, ob im Benutzerverzeichnis von ${User_List_gt_500} Log-Dateien sind.  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $(ls /Users/${User_List_gt_500}/Library/Logs/ | wc -l) -gt 0 ]; then
			printf "	%b	Es befinden sich Log-Dateien im Benutzerpfad. %s\\n"  | tee -a ${Audit_file}
			ls /Users/${User_List_gt_500}/Library/Logs/ >> ${evidence_folder}/SYS21M7_${User_List_gt_500}_Log-Dateien
			while read USER_LOG_FILES
			do
				printf "	%b		${USER_LOG_FILES} %s\\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS21M7_${User_List_gt_500}_Log-Dateien
		else
			printf "	%b	Es befinden sich keine Log-Dateien im Benutzerpfad. %s\\n"  | tee -a ${Audit_file}
		fi
		printf "\n"| tee -a ${Audit_file}
		done < ${Audit_folder}/TMP_User_List_gt_500
}

SYS21M7
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

##################################################
# 
# SYS.2.1.A8 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A8 Absicherung des Boot-Vorgangs %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Der Startvorgang des IT-Systems ("Booten") MUSS gegen Manipulation abgesichert werden. Es MUSS 
	festgelegt werden, von welchen Medien gebootet werden darf. Es SOLLTE entschieden werden, ob und
	wie der Bootvorgang kryptografisch geschützt werden soll. Es MUSS sichergestellt werden, dass nur 
	Administratoren die Clients von einem anderen als den voreingestellten Laufwerken oder externen 
	Speichermedien booten können. Nur Administratoren DÜRFEN von eingebauten optischen oder externen 
	Speichermedien booten können. Die Konfigurationseinstellungen des Boot-Vorgangs DÜRFEN nur durch 
	Benutzer mit administrativen Rechten verändert werden können. Alle nicht benötigten Funktionen 
	in der Firmware MÜSSEN deaktiviert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M8 ()

{
printf "	%b	Überprüfe, ob die Festplattenverschlüsselung FileVault aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}

FILEVAULTSTATUS=`fdesetup status -extended | grep "FileVault is" | awk ' { print $3 }'`
fdesetup status -extended >> ${evidence_folder}/SYS21M8_File_Vault_Status

if [ ${FILEVAULTSTATUS} == "Off." ]; then
	printf "	%b	Die Festplattenverschlüsselung FileVault ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Die Festplattenverschlüsselung FileVault ist aktiv. %s\\n" "${TICK}" | tee -a ${Audit_file}
			
	FILEVAULTVOLUME=`fdesetup status -extended | grep "Volume" | awk ' { print $3 }'`
			
	printf %s "		Es wird als Festplattenvolume genutzt: "${FILEVAULTVOLUME}"" | tee -a ${Audit_file}
	printf "\n" | tee -a ${Audit_file}
			
	sudo fdesetup list >> ${evidence_folder}/SYS21M8_FILEFAULTUSERS_List
	printf "	%b	Zeige die Kurznamen und UUIDs der freigegebenen FileVault-Benutzer. %s\\n" "${INFO}" | tee -a ${Audit_file}
		while read FILEFAULTUSERS
			do
				printf " 		\""${FILEFAULTUSERS}"\" \\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS21M8_FILEFAULTUSERS_List
						
	printf "\n" | tee -a ${Audit_file}
fi
	printf "\n" | tee -a ${Audit_file}
		
	printf "	%b	überprüfe, ob das EFI-Passwort unter macOS aktiv und auf den Wert \"Full-Modus\" gesetzt ist.  %s\\n" "${INFO}" | tee -a ${Audit_file}

sudo firmwarepasswd -verify 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_verify

if [ $(sudo firmwarepasswd -verify 2> /dev/null | grep -c "No firmware password set") == 1 ]; then
	printf "	%b	Das EFI-Passwort ist nicht gesetzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Das EFI-Passwort ist gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
    sudo firmwarepasswd -mode 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_mode
    sudo firmwarepasswd -check 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_check
fi
printf "\n" | tee -a ${Audit_file}
}

SYS21M8
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
#
# SYS.2.4.A1 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A1 Planung des sicheren Einsatzes von macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die Einführung von macOS MUSS sorgfältig geplant werden. Dabei MUSS ein Konzept zur Benutzerverwaltung,
 	zur Administration sowie zur Protokollierung erstellt werden. Es MUSS entschieden werden, wo und wie 
	Daten abgelegt werden. Es MUSS geplant werden, wie die Datensicherung in das institutionsweite 
 	Datensicherungskonzept integriert werden kann. Es MUSS geplant werden, wie der Schutz vor Schadprogrammen
 	in das institutionsweite Konzept integriert werden kann. Es MUSS geplant werden, wie Sicherheits- und
 	sonstige Aktualisierungen für macOS und Anwendungen systematisch installiert werden können.
 	Es MUSS ermittelt werden, welche Anwendungen bei einem Plattformwechsel zu macOS benötigt werden.
 	Wird der Mac in einem Datennetz betrieben, so MUSS zusätzlich berücksichtigt werden, welche Netzprotokolle
 	eingesetzt werden sollen." | tee -a ${Audit_file}

printf "\n\n"| tee -a ${Audit_file}


SYS24M1 ()
{
system_profiler SPHardwareDataType >> ${evidence_folder}/SYS24M1_System_Profil_Hardware_Type

printf "	Model Name: "${MODELNAME}" \\n" | tee -a ${Audit_file}
printf "	Model Identifier: "${MODELIDENTIFIER}" \\n" | tee -a ${Audit_file}
printf "	macOS Version: "${OSXVERSION}" \\n" | tee -a ${Audit_file}
printf "	Serial Number (system): "${SERIALNUMBER}" \\n" | tee -a ${Audit_file}
printf "	Hardware UUID: "${HW_UUID}" \\n" | tee -a ${Audit_file}

printf "\n" | tee -a ${Audit_file}

printf "	%b	Bitte das Infrastruktur- und Betriebsführungskonzept sowie Betriebshanbücher für dieses
		System angeben. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS24M1
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
# 
# SYS.2.4.A2 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A2 Nutzung der integrierten Sicherheitsfunktionen von macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die in macOS integrierten Schutzmechanismen System Integrity Protection (SIP), Xprotect und Gatekeeper
	MÜSSEN aktiviert sein. Gatekeeper DARF NUR die Ausführung signierter Programme erlauben, solange 
	unsignierte Programme nicht absolut nötig sind." | tee -a ${Audit_file}

printf "\n\n" | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.M2 SIP Status
#
###################################################

SYS24M2_SIP ()
{
printf "	%b	Überprüfung des System Integrity Protection (SIP) Status %s\\n" "${INFO}" | tee -a ${Audit_file}
SIPSTATUS=`csrutil status 2> /dev/null |  awk ' { print $5 }'`

csrutil status 2> /dev/null >> ${evidence_folder}/SYS24M2_System_Integrity_Status

if [ ${SIPSTATUS} == "enabled." ]; then
	printf "	%b	System Integrity Protection (SIP) ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	System Integrity Protection (SIP) ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi

printf "\n" | tee -a ${Audit_file}
}



###################################################
# 
# SYS.2.4.M2 Xprotect Status
#
###################################################

SYS24M2_Xprotect ()
{
printf "	%b	Überprüfung des Xprotect Status %s\\n" "${INFO}" | tee -a ${Audit_file}

defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist 2> /dev/null >> ${evidence_folder}/SYS24M2_XProtect

if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -gt 9 ]]; then

  last_xprotect_update_epoch_time=$(printf "%s\n" `for i in $(pkgutil --pkgs=".*XProtect.*"); do pkgutil --pkg-info $i | awk '/install-time/ {print $2}'; done` | sort -n | tail -1)
  last_xprotect_update_human_readable_time=`/bin/date -r "$last_xprotect_update_epoch_time" '+%d.%m.%Y %H:%M:%S'`
  XPROTECTCHECKRESULT="$last_xprotect_update_human_readable_time"
  printf "		Die letzte Xprotect Änderung erfolgte am "${XPROTECTCHECKRESULT}" \\n" | tee -a ${Audit_file}
  
fi

printf "\n\n" | tee -a ${Audit_file}
}



###################################################
# 
# SYS.2.4.M2 Gatekeeper Status
#
###################################################

SYS24M2_Gatekeeper ()
{
printf "	%b	Überprüfung des Gatekeeper Status %s\\n" "${INFO}" | tee -a ${Audit_file}

GATEKEEPERSTATUS=`spctl --status 2> /dev/null |  awk ' { print $2 }'`
spctl --status 2> /dev/null >> ${evidence_folder}/SYS24M2_Gatekeeper

if [ ${GATEKEEPERSTATUS} == "enabled" ]; then
	printf "	%b	Gatekeeper ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Gatekeeper ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
}


SYS24M2_SIP
sleep 0.5

SYS24M2_Xprotect
sleep 0.5

SYS24M2_Gatekeeper
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
# 
# SYS.2.4.A3 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A3 Verwaltung der Benutzerkonten %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Das bei der Erstkonfiguration von macOS angelegte Administrator-Konto DARF NUR zu administrativen 
	Zwecken verwendet werden. Für die normale Verwendung des Macs MUSS ein Standard-Benutzerkonto 
	angelegt werden. Sollte der Mac von mehreren Anwendern genutzt werden, MUSS für jeden
	Anwender ein eigenes Benutzerkonto angelegt werden. Das Gast-Benutzerkonto MUSS deaktiviert werden." | tee -a ${Audit_file}

printf "\n\n" | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.M3 Benutzer mit der ID 0
#
###################################################

SYS24M3_USERID_ROOT ()
{
printf "	%b	Auflistung der Konten, die als Benutzer mit der ID 0 hinterlegt sind. %s\\n" "${INFO}" | tee -a ${Audit_file}
ROOTMEMBER=`dscl . list /Users UniqueID | awk '$2 == 0 { print $1 }'` 
dscl . list /Users UniqueID >> ${evidence_folder}/SYS24M3_User_List

printf " 		Folgende Benutzer sind mit der ID 0 hinterlegt: "${ROOTMEMBER}"\\n" | tee -a ${Audit_file}
printf "\n" | tee -a ${Audit_file}

#

printf "	%b	Auflistung der Konten, die der Gruppe wheel zugehören. %s\\n" "${INFO}" | tee -a ${Audit_file}
}


###################################################
# 
# SYS.2.4.M3 Benutzer der Gruppe wheel
#
###################################################

SYS24M3_MEMBER_WHEEL ()
{

printf "	%b	Auflistung der Konten mit Systemrechten: %s\\n" "${INFO}" | tee -a ${Audit_file}

while read WHEEL_Member
	do
		if [[ $(dsmemberutil checkmembership -U "${WHEEL_Member}" -G wheel) == "user is a member of the group" ]]; then
		printf " 		der Benutzer \""${WHEEL_Member}"\" ist Mitglied der Gruppe wheel und besitzt administrative Systemrechte. \\n" | tee -a ${Audit_file}
    	fi
		
	done < ${evidence_folder}/TMP_User_List
	
	printf "\n" | tee -a ${Audit_file}

}


###################################################
# 
# SYS.2.4.M3 Benutzer mit UID > 500
#
###################################################

SYS24M3_USER_GREATER500 ()
{
printf "	%b	Auflistung der Konten mit UID größer 500: %s\\n" "${INFO}" | tee -a ${Audit_file}
dscl . list /Users UniqueID | awk '$2 > 500 { print $1 }' >> ${evidence_folder}/SYS24M3_User_List_gt_500

while read USER_gt_500
	do
		printf "  %b 		Das Benutzerkonto \""${USER_gt_500}"\" hat eine ID größer 500 %s\\n" | tee -a ${Audit_file}
	done < ${evidence_folder}/SYS24M3_User_List_gt_500
	
printf "\n\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.4.M3 Gast Account
#
###################################################

SYS24M3_USER_GUEST ()
{
printf "	%b	Überprüfe, ob das Gastkonto aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}

GASTKONTO=`defaults read /Library/Preferences/com.apple.loginwindow.plist | grep "GuestEnabled" | awk ' { print $3 }'`

if [ ${GASTKONTO} == "0;" ]; then
	printf "	%b	Gastkonto ist nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Gastkonto ist aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
		printf "\n" | tee -a ${Audit_file}
}

SYS24M3_USERID_ROOT
sleep 0.5

SYS24M3_MEMBER_WHEEL
sleep 0.5

SYS24M3_USER_GREATER500
sleep 0.5

SYS24M3_USER_GUEST
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
###################################################
#
#
# BSI - Standard-Anforderungen
#
#
###################################################
###################################################

printf %s "\
	Gemeinsam mit den Basis-Anforderungen entsprechen die folgenden
	Standard-Anforderungen dem Stand der Technik für den BSI IT-Grundschutz Bausteine \" SYS.2.4 Clients
	unter macOS\" und \"SYS.2.1 Allgemeiner Client\". Sie SOLLTEN grundsätzlich umgesetzt werden." | tee -a ${Audit_file}

printf "\n\n" | tee -a ${Audit_file}

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


##################################################
# 
# SYS.2.1.A9 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A9 Festlegung einer Sicherheitsrichtlinie für Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Ausgehend von der allgemeinen Sicherheitsrichtlinie der Institution SOLLTEN die Anforderungen an 
	allgemeine Clients konkretisiert werden. Die Richtlinie SOLLTE allen Benutzern sowie allen Personen, 
	die an der Beschaffung und dem Betrieb der Clients beteiligt sind, bekannt und Grundlage für deren 
	Arbeit sein. Die Umsetzung der in der Richtlinie geforderten Inhalte SOLLTE regelmäßig überprüft werden. 
	Die Ergebnisse SOLLTEN sinnvoll dokumentiert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M9 ()

{
	printf "	%b	Bitte das Sicherheitsmanagement hinsichtlich der Übergabe der aktuellen Sicherheitsrichtlinien anfragen.
		Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M9
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

##################################################
# 
# SYS.2.1.A10 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A10 Planung des Einsatzes von Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Zum sicheren Betrieb von Clients SOLLTE im Vorfeld geplant werden, wo und wie die Clients eingesetzt
	werden sollen. Die Planung SOLLTE dabei nicht nur Aspekte betreffen, die klassischerweise mit dem 
	Begriff Sicherheit verknüpft werden, sondern auch normale betriebliche Aspekte, die Anforderungen 
	im Bereich der Sicherheit nach sich ziehen. Neben Client-Typ-spezifischen Anforderungsprofilen SOLLTEN 
	Vorgaben zur Authentisierung und Benutzerverwaltung definiert werden. Alle Entscheidungen, die in der 
	Planungsphase getroffen wurden, SOLLTEN so dokumentiert werden, dass sie zu einem späteren Zeitpunkt 
	nachvollzogen werden können." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M10 ()

{
# duplicate from SYS.2.4.A1 Planung des sicheren Einsatzes von macOS	
printf "	Model Name: "${MODELNAME}" \\n" | tee -a ${Audit_file}
printf "	Model Identifier: "${MODELIDENTIFIER}" \\n" | tee -a ${Audit_file}
printf "	macOS Version: "${OSXVERSION}" \\n" | tee -a ${Audit_file}
printf "	Serial Number (system): "${SERIALNUMBER}" \\n" | tee -a ${Audit_file}
printf "	Hardware UUID: "${HW_UUID}" \\n" | tee -a ${Audit_file}

printf "\n" | tee -a ${Audit_file}

	printf "	%b	Bitte das Infrastruktur- und Betriebsführungskonzept sowie Betriebshanbücher für dieses
		System angeben. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M10
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

##################################################
# 
# SYS.2.1.A11 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A11 Beschaffung von Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bevor Clients beschafft werden, SOLLTE eine Anforderungsliste erstellt werden, anhand derer die am 
	Markt erhältlichen Produkte bewertet werden. Der jeweilige Hersteller SOLLTE für den gesamten 
	geplanten Nutzungszeitraum Patches für Schwachstellen zeitnah zur Verfügung stellen können. 
	Die zu beschaffenden Systeme SOLLTEN über eine Firmware-Konfigurationsoberfläche für UEFI SecureBoot
	und für das TPM (sofern vorhanden) verfügen, die eine Kontrolle durch den Eigentümer (Institution) 
	gewährleistet und so den selbstverwalteten Betrieb von SecureBoot und des TPM ermöglicht." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M11 ()

{
	printf "	%b	Bitte die Auflistung der Use-Cases und Anforderungslisten auf deren Basis die macOS-Clienst beschafft wurden angeben.
		Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M11
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A12 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A12 Kompatibilitätsprüfung von Software %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Vor einer beabsichtigten Beschaffung von Software SOLLTE deren Kompatibilität zum eingesetzten 
	Betriebssystem in der vorliegenden Konfiguration geprüft und die Kompatibilitätsprüfung in das 
	Freigabeverfahren der Software aufgenommen werden. Ist vom Hersteller der Software oder aus 
	anderen Fachkreisen keine verbindliche Information zur Kompatibilität vorhanden, so SOLLTE die 
	Kompatibilität in einer Testumgebung geprüft werden. Vor einer beabsichtigten Hardwareänderung 
	oder bei einer Betriebssystemmigration SOLLTE auch die Treibersoftware für alle betreffenden 
	Komponenten auf Kompatibilität zum Betriebssystem gewährleistet werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M12 ()

{
	printf "	%b	Überprüfe, ob aktuell 32-Bit Software auf dem System installiert ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	local COUNT_32_BIT_Software=`system_profiler SPApplicationsDataType | grep -c "64-Bit (Intel): No"`
	if [ ${COUNT_32_BIT_Software} -gt 0 ]; then
		printf "	%b	Es sind aktuell noch \"${COUNT_32_BIT_Software}\" 32-Bit Anwendungen auf dem System installiert. 
		Diese sind inkompatible für macOS 10.14 (Mojave). %s\\n" "${CROSS}"	 | tee -a ${Audit_file}
		printf "	%b	Hier von betroffen sind: %s\\n" "${INFO}"	 | tee -a ${Audit_file}
		system_profiler SPApplicationsDataType | grep -A3 -B7 "64-Bit (Intel): No" | sed '/--/d' >> ${evidence_folder}/SYS21M12_macOS_Mojave_incompatible
		while read macOS_Mojave_incompatible
			do
				printf "	%b	${macOS_Mojave_incompatible} %s\\n" | tee -a ${Audit_file}		
		done < ${evidence_folder}/SYS21M12_macOS_Mojave_incompatible
		printf "\n"| tee -a ${Audit_file}
	else
		printf "	%b	Es sind aktuell keine 32-Bit Anwendungen auf dem System installiert ist. 
		Alle Anwendungen sind kompatible für macOS 10.14 (Mojave). %s\\n" "${TICK}"	 | tee -a ${Audit_file}
	fi
	printf "	%b	Zugrundeliegende Anforderungs- bzw. Migrationsprozesse bitte benennen. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	printf "	%b	Da diese nicht technisch geprüft werden können.	%s\\n" 	 | tee -a ${Audit_file}
	printf "\n"| tee -a ${Audit_file}
}

SYS21M12
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A13 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A13 Zugriff auf Ausführungsumgebungen mit unbeobachtbarer Codeausführung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Der Zugriff auf Ausführungsumgebungen mit unbeobachtbarer Codeausführung (z. B. durch das Betriebssystem 
	speziell abgesicherte Speicherbereiche, Firmwarebereiche etc.) SOLLTE nur durch Benutzer mit 
	administrativen Berechtigungen möglich sein. Die entsprechenden Einstellungen im BIOS bzw. der 
	UEFI-Firmware SOLLTEN durch ein Passwort gegen Veränderungen geschützt werden. Wird die Kontrolle
	über die Funktionen an das Betriebssystem delegiert, dann SOLLTEN dort auch nur Benutzer mit 
	administrativen Berechtigungen die Funktionen kontrollieren dürfen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

###################################################
# 
# SYS.2.1.M13 EFI Password
#
###################################################

SYS21M13_Firmware_password ()
{
printf "	%b	überprüfe, ob das EFI-Passwort unter macOS aktiv und auf den Wert \"Full-Modus\" gesetzt ist.  %s\\n" "${INFO}" | tee -a ${Audit_file}

sudo firmwarepasswd -verify 2> /dev/null >> ${evidence_folder}/SYS21M13_EFI_Password_verify

if [ $(sudo firmwarepasswd -verify 2> /dev/null | grep -c "No firmware password set") == 1 ]; then
	printf "	%b	Das EFI-Passwort ist nicht gesetzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Das EFI-Passwort ist gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
    sudo firmwarepasswd -mode 2> /dev/null >> ${evidence_folder}/SYS21M13_EFI_Password_mode
    sudo firmwarepasswd -check 2> /dev/null >> ${evidence_folder}/SYS21M13_EFI_Password_check
fi
printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M13 Benutzer mit der ID 0
#
###################################################

SYS21M13_USERID_ROOT ()
{
printf "	%b	Auflistung der Konten, die als Benutzer mit der ID 0 hinterlegt sind. %s\\n" "${INFO}" | tee -a ${Audit_file}
ROOTMEMBER=`dscl . list /Users UniqueID | awk '$2 == 0 { print $1 }'` 
dscl . list /Users UniqueID >> ${evidence_folder}/SYS21M13_User_List

printf " 		Folgende Benutzer sind mit der ID 0 hinterlegt: "${ROOTMEMBER}"\\n" | tee -a ${Audit_file}
printf "\n" | tee -a ${Audit_file}

}

###################################################
# 
# SYS.2.1.M13 Wird der Benutzer root genutzt
#
###################################################

SYS21M13_ROOT_activ ()
{
printf "	%b	Überprüfe, ob Benutzer root aktiv genutzt wird. %s\\n" "${INFO}" | tee -a ${Audit_file}	
if [ $(dscl . -read /Users/root | grep -c "ShadowHash") != 0 ]; then
	printf "	%b	Der Benutzer root wird aktiv genutzt. Bitte sudo anstelle von root benutzen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Dder Benutzer root ist nicht aktiviert worden. %s\\n" "${TICK}" | tee -a ${Audit_file}
fi
printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M13 Benutzer der Gruppe wheel
#
###################################################

SYS21M13_MEMBER_WHEEL ()
{

printf "	%b	Auflistung der Konten mit Systemrechten: %s\\n" "${INFO}" | tee -a ${Audit_file}

while read WHEEL_Member
	do
		if [[ $(dsmemberutil checkmembership -U "${WHEEL_Member}" -G wheel) == "user is a member of the group" ]]; then
		printf " 		der Benutzer \""${WHEEL_Member}"\" ist Mitglied der Gruppe wheel und besitzt administrative Systemrechte. \\n" | tee -a ${Audit_file}
    	fi
		
	done < ${evidence_folder}/TMP_User_List
	
	printf "\n" | tee -a ${Audit_file}

}

###################################################
# 
# SYS.2.1.M13 Benutzer der Gruppe admin
#
###################################################


SYS21M13_MEMBER_ADMIN ()
{
printf "	%b	Auflistung der Konten mit administrativen Rechten: %s\\n" "${INFO}" | tee -a ${Audit_file}

while read ADMIN_Member
	do
		if [[ $(dsmemberutil checkmembership -U "${ADMIN_Member}" -G admin) == "user is a member of the group" ]]; then
		printf " 		der Benutzer \""${ADMIN_Member}"\" ist Mitglied der Gruppe admin. \\n" | tee -a ${Audit_file}
    	fi
		
	done < ${evidence_folder}/TMP_User_List
	
printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M13 nur admin dürfen systemänderungen durchführen
#
###################################################


SYS21M13_ONLY_ADMIN_AllOWED_SyS_Changes ()
{
printf "	%b	Überprüfe, ob nur Administratoren systemnahe Einstellungen ändern durchführen dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
	local SYSCHANGESONLYADMIN=`security authorizationdb read  system.preferences 2> /dev/null | grep -A1 "shared" | grep -c "false/"`
	if [[ ${SYSCHANGESONLYADMIN} == 1 ]]; then
		printf "	%b	Nur Administratoren dürfen Änderungen an systemnahen Einstellungen vornehmen. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Nicht nur Administratoren dürfen Änderungen an systemnahen Einstellungen vornehmen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi		

printf "\n" | tee -a ${Audit_file}
}

SYS21M13_Firmware_password
sleep 0.5

SYS21M13_USERID_ROOT
sleep 0.5

SYS21M13_ROOT_activ 
sleep 0.5

SYS21M13_MEMBER_WHEEL
sleep 0.5

SYS21M13_MEMBER_ADMIN
sleep 0.5

SYS21M13_ONLY_ADMIN_AllOWED_SyS_Changes
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A14 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A14 Updates und Patches für Firmware, Betriebssystem und Anwendungen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Administratoren SOLLTEN sich regelmäßig über bekannt gewordene Schwachstellen informieren. 
	Die identifizierten Schwachstellen SOLLTEN so schnell wie möglich behoben werden. Generell 
	SOLLTE darauf achtet werden, dass Patches und Updates nur aus vertrauenswürdigen Quellen 
	bezogen werden. Wenn notwendig, SOLLTEN die betreffenden Anwendungen beziehungsweise das 
	Betriebssystem nach dem Update neu gestartet werden.

	Solange keine entsprechenden Patches zur Verfügung stehen, SOLLTEN abhängig von der Schwere
	der Schwachstellen andere geeignete Maßnahmen zum Schutz des IT-Systems getroffen werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M14 ()

{
	printf "	%b	Bitte bei den den verantwortlichen Administratoren anfragen über welche Quellen 
		sich diese über aktuelle Schwachstellen des Betriebssystems und der eingesetzten Software 
		informieren. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M14
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A15 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A15 Sichere Installation und Konfiguration von Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE festgelegt werden, welche Komponenten des Betriebssystems, Fachanwendungen und weitere 
	Tools installiert werden sollen. Die Installation und Konfiguration der IT-Systeme SOLLTE nur von 
	autorisierten Personen (Administratoren oder vertraglich gebundene Dienstleister) nach einem 
	definierten Prozess durchgeführt werden. Alle Installations- und Konfigurationsschritte SOLLTEN 
	so dokumentiert werden, dass die Installation und Konfiguration durch einen sachkundigen Dritten 
	anhand der Dokumentation nachvollzogen und wiederholt werden kann.
	
	Die Grundeinstellungen von Clients SOLLTEN überprüft und nötigenfalls entsprechend den Vorgaben 
	der Sicherheitsrichtlinie angepasst werden. Erst nachdem die Installation und die Konfiguration
	abgeschlossen sind, SOLLTE der Client mit dem Internet verbunden werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}
SYS21M15 ()

{
	printf "	%b	Bitte das Infrastruktur- und Betriebsführungskonzept sowie Betriebshanbücher für dieses
		System angeben. Diese Dokumentation dient als Grundlage für die technische Prüfung. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M15
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A16 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A16 Deaktivierung und Deinstallation nicht benötigter Komponenten und Kennungen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Nach der Installation SOLLTE überprüft werden, welche Komponenten der Firmware, des Betriebssystems, 
	welche Anwendungen und weiteren Tools auf den Clients installiert und aktiviert sind. Nicht benötigte 
	Module, Programme, Dienste, Benutzerkennungen und Schnittstellen SOLLTEN deaktiviert oder ganz 
	deinstalliert werden. Außerdem SOLLTEN nicht benötigte Laufzeitumgebungen, Interpretersprachen und 
	Compiler deinstalliert werden. Entsprechende nicht benötigte, jedoch fest mit dem IT-System verbundene 
	Komponenten SOLLTEN deaktiviert werden. Auch in der Firmware vorhandene nicht benötigte Komponenten 
	SOLLTEN abgeschaltet werden. Es SOLLTE verhindert werden, dass diese Komponenten wieder reaktiviert 
	werden können. Die getroffenen Entscheidungen SOLLTEN so dokumentiert werden, dass nachvollzogen werden 
	kann, welche Konfiguration und Softwareausstattung für die IT-Systeme gewählt wurden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M16 ()

{

printf "	%b	Überprüfe, ob via Profilmanager das System ${MODELIDENTIFIER} verwaltet wird.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(system_profiler SPConfigurationProfileDataType | wc -l) -gt 0 ] ; then
	system_profiler SPConfigurationProfileDataType >> ${evidence_folder}/SYS21M16_SPConfigurationProfileDataType
	printf "	%b	Das System ${MODELIDENTIFIER} wird mittels Profilen verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# DisabledPreferencePanes
	#
	#################################################	
	printf "	%b	Überprüfe, ob die Zugriffe auf das Preference-Panels reduziert sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | sed -n '/DisabledPreferencePanes/,/);/p' | wc -l) -gt 0 ]] ; then
		system_profiler SPConfigurationProfileDataType | sed -n '/DisabledPreferencePanes/,/);/p' | sed 's/);//g' | sed 's/DisabledPreferencePanes =     (//g' >> ${evidence_folder}/SYS21M16_DisabledPreferencePanes
		printf "	%b	Folgende Zugriffe auf das Preference-Panels sind reduziert. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
		while read DisabledPreferencePanes
		do
			printf "	%b	${DisabledPreferencePanes} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M16_DisabledPreferencePanes
	else
		printf "	%b	Es sind keine reduzierten Zugriffe auf das Preference-Panels hinterlegt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
	
	printf "\n" | tee -a ${Audit_file}

	#################################################
	# 
	# AllowedShareServices
	#
	#################################################	

	printf "	%b	Überprüfe, welche Plugin-IDs im Menü - Share des Benutzers - erlaubt und angezeigt werden. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | sed -n '/SHKAllowedShareServices/,/);/p' | wc -l) -gt 0 ]] ; then
		system_profiler SPConfigurationProfileDataType | sed -n '/SHKAllowedShareServices/,/);/p' | sed 's/);//g' | sed 's/SHKAllowedShareServices =     (//g' >> ${evidence_folder}/SYS21M16_SHKAllowedShareServices
		
		while read SHKAllowedShareServices
		do
			printf "	%b	${SHKAllowedShareServices} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M16_SHKAllowedShareServices
		
	fi
	
	printf "\n" | tee -a ${Audit_file}

	#################################################
	# 
	# allowCloudNotes
	#
	#################################################
	
	printf "	%b	Überprüfe, ob iCloud-Notizen erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudNotes"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	iCloud-Notizen sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	iCloud-Notizen sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi
	
	#################################################
	# 
	# allowCloudAddressBook
	#
	#################################################
	
	printf "	%b	Überprüfe, ob das iCloud-Adressbuch erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudAddressBook"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Das iCloud-Adressbuch ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Das iCloud-Adressbuch ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi	
	
	#################################################
	# 
	# allowCloudBookmarks
	#
	#################################################
	
	printf "	%b	Überprüfe, ob iCloud-Bookmarks erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudBookmarks"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	iCloud-Bookmarks sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	iCloud-Bookmarks sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi	
	
	
	#################################################
	# 
	# allowCloudCalendar
	#
	#################################################
	
	printf "	%b	Überprüfe, ob der iCloud-Kalender erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudCalendar"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Der iCloud-Kalender ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Der iCloud-Kalender ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowCloudDesktopAndDocuments
	#
	#################################################
	
	printf "	%b	Überprüfe, ob der iCloud-Schreibtisch und Dokumete erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudDesktopAndDocuments"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Der Cloud-Schreibtisch und Dokumete sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Der Cloud-Schreibtisch und Dokumete sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi	
	
	#################################################
	# 
	# allowCloudDocumentSync
	#
	#################################################
	
	printf "	%b	Überprüfe, ob die Synchronitation von Dokumenten in die iCloud erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudDocumentSync"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Die Synchronitation von Dokumenten in die iCloud sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die Synchronitation von Dokumenten in die iCloud sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowCloudKeychainSync
	#
	#################################################
	
	printf "	%b	Überprüfe, ob die Synchronitation des Schlüsselbundes in die iCloud erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudDocumentSync"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Die Synchronitation des Schlüsselbundes in die iCloud ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die Synchronitation des Schlüsselbundes in die iCloud ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	#################################################
	# 
	# DisableUsingiCloudPassword
	#
	#################################################
	
	printf "	%b	Überprüfe, ob iCloud-Passwörter für lokale Accounts erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "DisableUsingiCloudPassword"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	iCloud-Passwörter für lokale Accounts sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	iCloud-Passwörter für lokale Accounts sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowCloudMail
	#
	#################################################
	
	printf "	%b	Überprüfe, ob die Synchronitation von Mails in die iCloud erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudMail"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Die Synchronitation von Mails in die iCloud ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die Synchronitation von Mails in die iCloud ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowCloudReminders
	#
	#################################################
	
	printf "	%b	Überprüfe, ob die Synchronitation von Erinnerungen in die iCloud erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowCloudReminders"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Die Synchronitation von Erinnerungen in die iCloud ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die Synchronitation von Erinnerungen in die iCloud ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowiTunesFileSharing
	#
	#################################################
	
	printf "	%b	Überprüfe, ob iTunes-Dateifreigaben erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowiTunesFileSharing"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Die iTunes-Dateifreigaben sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Die iTunes-Dateifreigaben sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		

	#################################################
	# 
	# allowContentCaching
	#
	#################################################
	
	printf "	%b	Überprüfe, ob Content-Caching erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowContentCaching"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Das Content-Caching ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Das Content-Caching ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi			

	#################################################
	# 
	# allowFingerprintForUnlock
	#
	#################################################
	
	printf "	%b	Überprüfe, ob der Fingerprint zum Entsprerren erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowFingerprintForUnlock"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Der Fingerprint zum Entsprerren ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Der Fingerprint zum Entsprerren ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi

	#################################################
	# 
	# allowMusicService
	#
	#################################################
	
	printf "	%b	Überprüfe, ob Apple Music erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowMusicService"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Apple Music ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Apple Music ist erlaubt. %s\\n\n" "${ATTENTION}" | tee -a ${Audit_file}
	fi	

	#################################################
	# 
	# allowSpotlightInternetResults
	#
	#################################################
	
	printf "	%b	Überprüfe, ob Spotlight-Internet-Vorschläge erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowSpotlightInternetResults"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Spotlight-Internet-Vorschläge sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Spotlight-Internet-Vorschläge sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi	
	
	#################################################
	# 
	# DisableAirDrop
	#
	#################################################
	
	printf "	%b	Überprüfe, ob Airdrop erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "DisableAirDrop"| awk ' { print $3 }') == "1;" ]] ; then
		printf "	%b	Airdrop ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Airdrop ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# allowSpotlightInternetResults
	#
	#################################################
	
	printf "	%b	Überprüfe, ob Spotlight-Internet-Vorschläge erlaubt sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "allowSpotlightInternetResults"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Spotlight-Internet-Vorschläge sind nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Spotlight-Internet-Vorschläge sind erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	fi		
	
	#################################################
	# 
	# GKFeatureGameCenterAllowed
	#
	#################################################
	
	printf "	%b	Überprüfe, ob das Game-Center erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "GKFeatureGameCenterAllowed"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Das Game-Center ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Das Game-Center ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
		
			#################################################
			# 
			# GKFeatureMultiplayerGamingAllowed
			#
			#################################################
	
			printf "	%b	Überprüfe, ob im Game-Center der Mehrspielermodus erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
			if [[ $(system_profiler SPConfigurationProfileDataType | grep "GKFeatureMultiplayerGamingAllowed"| awk ' { print $3 }') == "0;" ]] ; then
				printf "	%b	Der Mehrspielermodus ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Der Mehrspielermodus ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		
			#################################################
			# 
			# GKFeatureAddingGameCenterFriendsAllowed
			#
			#################################################
	
			printf "	%b	Überprüfe, ob im Game-Center das Hinzufügen von Freunden erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
			if [[ $(system_profiler SPConfigurationProfileDataType | grep "GKFeatureAddingGameCenterFriendsAllowed"| awk ' { print $3 }') == "0;" ]] ; then
				printf "	%b	Das Hinzufügen von Freunden ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Das Hinzufügen von Freunden ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
			fi
			
			#################################################
			# 
			# GKFeatureAccountModificationAllowed
			#
			#################################################
	
			printf "	%b	Überprüfe, ob im Game-Center das Ändern des Accounts erlaubt ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
			if [[ $(system_profiler SPConfigurationProfileDataType | grep "GKFeatureAccountModificationAllowed"| awk ' { print $3 }') == "0;" ]] ; then
				printf "	%b	Das Ändern des Accounts ist nicht erlaubt. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Das Ändern des Accounts ist erlaubt. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
			fi						
		
	fi			
	
	#################################################
	# 
	# whiteListEnabled
	#
	#################################################
	
	printf "	%b	Überprüfe, ob für das Dashboard eine Whitelist aktiviert wurde. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(system_profiler SPConfigurationProfileDataType | grep "whiteListEnabled"| awk ' { print $3 }') == "0;" ]] ; then
		printf "	%b	Für das Dashboard wurde keine Whitelist aktiviert. %s\\n\n" "${CROSS}" | tee -a ${Audit_file}
	else
		printf "	%b	Für das Dashboard wurde eine Whitelist aktiviert. %s\\n\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Zeige, welche Widgets per Whitelist erlaubt sind: %s\\n" "${INFO}"	 | tee -a ${Audit_file}
		system_profiler SPConfigurationProfileDataType | sed -n '/WhiteList =     (/,/);/p' | grep "mcx_DisplayName" | sed 's/"mcx_DisplayName" = //g' | sed 's/;//g' >> ${evidence_folder}/SYS21M16_Dashboard_whiteListEnabled
		
				while read whiteListEnabledWidgets
		do
			printf "	%b	${whiteListEnabledWidgets} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M16_Dashboard_whiteListEnabled
	fi			
	
else
	printf "	%b	Es ist kein Profilemanager hinterlegt. %s\\n" "${CROSS}" | tee -a ${Audit_file}

	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob die Anwendung OverSight für die Überwachung von Webcam und Mikrofon-Aktivitäten installiert ist. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	system_profiler SPApplicationsDataType >> ${evidence_folder}/SYS21M16_all_installed_Apps
	
	if [[ $(cat ${evidence_folder}/SYS21M16_all_installed_Apps | grep -c "OverSight:") -gt 0 ]] ; then
		printf "	%b	Die Anwendung OverSight von Patrick Wardle ist installiert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	folgende Informationen zur Anwendung wurden gefunden. %s\\n\n" | tee -a ${Audit_file}
		cat ${evidence_folder}/SYS21M16_all_installed_Apps | sed -n '/OverSight:/,/.app/p' >> ${evidence_folder}/SYS21M16_monitor_mic_and_webcam_app
		
		while read monitor_mic_and_webcam_app
		do
			printf "	%b	${monitor_mic_and_webcam_app} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M16_monitor_mic_and_webcam_app
	else
		printf "	%b	Die Anwendung OverSight https://objective-see.com/products/oversight.html 
			für die Überwachung von Webcam und Mikrofon-Aktivitäten ist nicht installiert. %s\\n" | tee -a ${Audit_file}
		printf "	%b	Falls eine alternative Anwendung genutzt wird diese bitte angeben. %s\\n" | tee -a ${Audit_file}
	fi
	
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# Kernelmodule
	#
	#################################################
	ls /System/Library/Extensions/ >> ${evidence_folder}/SYS21M16_all_active_KEXT_files

		#################################################
		# 
		# Kernelmodul - IOUSBMassStorageClass
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) IOUSBMassStorageClass.kext für USB-Wechselmedien installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/IOUSBMassStorageClass.kext ]; then
			printf "	%b	Das Kernebundel IOUSBMassStorageClass.kext für USB-Wechselmedien ist installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel IOUSBMassStorageClass.kext für USB-Wechselmedien ist nicht installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert %s\\n" | tee -a ${Audit_file}		
		fi	
	
		printf "\n" | tee -a ${Audit_file}
		
		#################################################
		# 
		# Kernelmodul - IOBluetoothHIDDriver
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) IOBluetoothHIDDriver.kext für Human Interface Devices (HID) installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/IOBluetoothHIDDriver.kext ]; then
			printf "	%b	Das Kernebundel IOBluetoothHIDDriver.kext für Human Interface Devices (HID) ist installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel IOBluetoothHIDDriver.kext für Human Interface Devices (HID) ist nicht installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert %s\\n" | tee -a ${Audit_file}		
		fi	
	
		printf "\n" | tee -a ${Audit_file}
	
		#################################################
		# 
		# Kernelmodul - IOBluetoothFamily
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) IOBluetoothFamily.kext für die Nutzung von Bluetooth installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/IOBluetoothFamily.kext ]; then
			printf "	%b	Das Kernebundel IOBluetoothFamily.kext für die Nutzung von Bluetooth ist installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel IOBluetoothFamily.kext für die Nutzung von Bluetooth ist nicht installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert %s\\n" | tee -a ${Audit_file}		
		fi	
	
		printf "\n" | tee -a ${Audit_file}
	
		#################################################
		# 
		# Kernelmodul - Wi-Fi / WLAN
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) IO80211Family.kext für die Nutzung von WLAN installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/IO80211Family.kext ]; then
			printf "	%b	Das Kernebundel IO80211Family.kext für die Nutzung von WLAN ist installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel IO80211Family.kext für die Nutzung von WLAN ist nicht installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert %s\\n" | tee -a ${Audit_file}		
		fi
	
		printf "\n" | tee -a ${Audit_file}
	
		#################################################
		# 
		# Kernelmodul - IR-Controller
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) AppleIRController.kext für die Nutzung des IR-Controllers installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/AppleIRController.kext ]; then
			printf "	%b	Das Kernebundel AppleIRController.kext für die Nutzung des IR-Controllers ist installiert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel AppleIRController.kext für die Nutzung des IR-Controllers ist nicht installiert. %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert. %s\\n" | tee -a ${Audit_file}		
		fi	
	
		printf "\n" | tee -a ${Audit_file}
	
		#################################################
		# 
		# Kernelmodul - iSight
		#
		#################################################	
		printf "	%b	Überprüfe, ob das Kernebundel (KEXT) Apple_iSight.kext für die Nutzung der iSight Kamera installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /System/Library/Extensions/Apple_iSight.kext ]; then
			printf "	%b	Das Kernebundel Apple_iSight.kext für die Nutzung der iSight Kamera ist installiert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Das Kernebundel Apple_iSight.kext für die Nutzung der iSight Kamera ist nicht installiert. %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert. %s\\n" | tee -a ${Audit_file}		
		fi	
	
	
fi
printf "\n" | tee -a ${Audit_file}	
}

SYS21M16
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A17 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A17 Einsatzfreigabe %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bevor der Client im produktiven Betrieb eingesetzt und bevor er an ein produktives Netz angeschlossen 
	wird, SOLLTE eine Einsatzfreigabe erfolgen. Diese SOLLTE dokumentiert werden. Für die Einsatzfreigabe 
	SOLLTE die Installations- und Konfigurationsdokumentation und die Funktionsfähigkeit der IT-Systeme 
	in einem Test geprüft werden. Sie SOLLTE durch eine in der Institution dafür autorisierte Stelle erfolgen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M17 ()

{
	printf "	%b	Bitte das Dokument, welches die finale Freigabe für den produktiven Einsatz von macOS freigibt benennen.
		Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M17
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A18 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A18 Nutzung von TLS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Kommunikationsverbindungen SOLLTEN durch Verschlüsselung geschützt werden, soweit möglich. 
	Benutzer SOLLTEN darauf achten, dass bei Web-Seiten SSL/TLS verwendet wird.

	Der IT-Betrieb SOLLTE dafür sorgen, dass die eingesetzten Client-Produkte eine sichere Version 
	von TLS unterstützen. Die Clients SOLLTEN kryptografische Algorithmen und Schlüssellängen 
	verwenden, die dem Stand der Technik und den Sicherheitsanforderungen der Institution entsprechen.

	Neue Zertifikate SOLLTEN erst nach Überprüfung des "Fingerprints" aktiviert werden. Die Validierung
	von Zertifikaten SOLLTE in Anwendungsprogrammen wie Browsern und E-Mail-Clients aktiviert werden. 
	Session Renegotiation und TLS-Kompression SOLLTEN deaktiviert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M18 ()

{
	printf "	%b	Überprüfe, ob LibreSSL oder openssl unter macOS als Standard verwendet wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local open_or_libre=`openssl version | awk ' { print $1 }'`
		if [[ ${open_or_libre} == "LibreSSL" ]] ; then
			printf "	%b	Es ist wird LibreSSL als Standard verwendet.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Es ist wird nicht LibreSSL als Standard verwendet.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi		
		
	printf "	%b	Überprüfe, welche SSL ciphers vom Betriebssystem bereitgestellt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
		openssl ciphers | tr ':' '\n' >> ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS
		openssl ciphers | tr ':' '\n' | grep  "SHA" | grep -v "SHA256" | grep -v "SHA384" >> ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_WITH_SHA1
		openssl ciphers | tr ':' '\n' | grep  "RC4" >> ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_RC4
		openssl ciphers | tr ':' '\n' | grep  "DES" >> ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_DES
				
		while read ALL_SSL_CIPHER
		do
			printf "	%b		${ALL_SSL_CIPHER} %s\\n" | tee -a ${Audit_file}
	
		done < ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS
	
		printf "	%b	SSL cipher mit RC4, DES, SHA1 und MD5 sollten nicht mehr verwendet werden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Diese SSL Cipher nutzen SHA1: %s\\n" | tee -a ${Audit_file}
		while read SSL_CIPHERS_WITH_SHA1
		do
			printf "	%b		${SSL_CIPHERS_WITH_SHA1} %s\\n" | tee -a ${Audit_file}
	
		done < ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_WITH_SHA1
		
	printf "\n"| tee -a ${Audit_file}	
	
		printf "	%b	Diese SSL Cipher nutzen DES: %s\\n" | tee -a ${Audit_file}
		while read SSL_CIPHERS_WITH_DES
		do
			printf "	%b		${SSL_CIPHERS_WITH_DES} %s\\n" | tee -a ${Audit_file}
	
		done < ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_DES

	
	printf "\n"| tee -a ${Audit_file}	
	
		printf "	%b	Diese SSL Cipher nutzen RC4: %s\\n" | tee -a ${Audit_file}
		while read SSL_CIPHERS_WITH_RC4
		do
			printf "	%b		${SSL_CIPHERS_WITH_RC4} %s\\n" | tee -a ${Audit_file}
	
		done < ${evidence_folder}/SYS21M13_OPENSSL_CIPHERS_RC4
	
	printf "\n"| tee -a ${Audit_file}
		
	printf "	%b	Die Unterstützung von TLS 1.0 und 1.1 wird von Apple nicht mehr empfohlen. Der vollständige Support wird durch ein Update 
		von Apple ab März 2020 aus Safari entfernt. Weitere Information können hier nachgelesen werden: 
		https://webkit.org/blog/8462/deprecation-of-legacy-tls-1-0-and-1-1-versions/ %s\\n" "${INFO}" | tee -a ${Audit_file}
		
	printf "\n"| tee -a ${Audit_file}
}

SYS21M18
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A19 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A19 Restriktive Rechtevergabe %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Der verfügbare Funktionsumfang des IT-Systems SOLLTE für einzelne Benutzer oder Benutzergruppen 
	eingeschränkt werden, sodass sie genau die Rechte besitzen und auf die Funktionen zugreifen können,
	die sie für ihre Aufgabenwahrnehmung benötigen. Zugriffsberechtigungen SOLLTEN hierfür möglichst 
	restriktiv vergeben werden. Es SOLLTE regelmäßig überprüft werden, ob die Berechtigungen, 
	insbesondere für Systemverzeichnisse und -dateien, den Vorgaben der Sicherheitsrichtlinie entsprechen. 
	Auf Systemdateien SOLLTEN möglichst nur die Systemadministratoren Zugriff haben. Der Kreis der 
	zugriffsberechtigten Administratoren SOLLTE möglichst klein gehalten werden. Auch System-Verzeichnisse 
	SOLLTEN nur die notwendigen Privilegien für die Benutzer zur Verfügung stellen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M19 ()

{
while read User_List_gt_500
	do 
		printf "	%b	überprüfe, ob alle Dateien im Benutzerpfad vom Benutzer ${User_List_gt_500} ihm auch gehören.  %s\\n" "${INFO}" | tee -a ${Audit_file}
			find /Users/${User_List_gt_500} ! -user ${User_List_gt_500} -print >> ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_Owner_mismatch
			
			if [[ $(cat ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_Owner_mismatch | wc -l) -gt 0 ]] ; then
				printf "	%b	Diese Dateien im Benutzerpfad gehören nicht dem Benutzer ${User_List_gt_500}. %s\\n" "${CROSS}" | tee -a ${Audit_file}
				while read LOG_FILE_Owner_mismatch 
					do
						printf "	%b		${LOG_FILE_Owner_mismatch} %s\\n" | tee -a ${Audit_file}
					done < ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_Owner_mismatch
			else
				printf "	%b	Alle Dateien im Benutzerpfad gehören dem Benutzer ${User_List_gt_500}. %s\\n" "${TICK}" | tee -a ${Audit_file}
			fi
		printf "\n"| tee -a ${Audit_file}
		
		printf "	%b	überprüfe, ob alle Dateien im Benutzerpfad vom Benutzer ${User_List_gt_500} auch seinen zugehörigen Gruppen gehören.  %s\\n" "${INFO}" | tee -a ${Audit_file}
		groups ${User_List_gt_500} | sed 's/ / -a ! -group /g' >> ${evidence_folder}/SYS21M19_${User_List_gt_500}_groups
		find /Users/${User_List_gt_500} ! -group $(cat ${evidence_folder}/SYS21M19_${User_List_gt_500}_groups) -print >> ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_GROUP_mismatch
				local file_count="$(cat ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_GROUP_mismatch | grep -c "^/")"
		if [[ $(cat ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_GROUP_mismatch | grep -c "^/") -gt 0 ]] ; then
			
			printf "	%b	Diese Dateien im Benutzerpfad gehören nicht einer Gruppe vom Benutzer ${User_List_gt_500} an. %s\\n" "${CROSS}" | tee -a ${Audit_file}
			while read LOG_FILE_Group_mismatch
				do
					printf "	%b		${LOG_FILE_Group_mismatch} %s\\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS21M19_${User_List_gt_500}_LOG_FILE_GROUP_mismatch
		else
			printf "	%b	Alle Dateien im Benutzerpfad gehören dem Benutzer ${User_List_gt_500} und seinen Gruppen. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	
		printf "\n"| tee -a ${Audit_file}
	done < ${Audit_folder}/TMP_User_List_gt_500
}

SYS21M19
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

#################################################
# 
# SYS.2.1.A20 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A20 Schutz der Administrationsschnittstellen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Abhängig davon, ob Clients lokal, über das Netz oder über zentrale netzbasierte Tools administriert 
	werden, SOLLTEN geeignete Sicherheitsvorkehrungen getroffen werden. Die zur Administration verwendeten
	Methoden SOLLTEN in der Sicherheitsrichtlinie festgelegt und die Administration SOLLTE entsprechend 
	der Sicherheitsrichtlinie durchgeführt werden. Die Administration über das Netz SOLLTE über sichere 
	Protokolle erfolgen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

################################################
# 
# SYS.2.1.M20 BSI - Remote Desktop Apps
#
###################################################

SYS21M20_Remotemanagement_Apps ()

{
	printf "	%b	Überprüfe, ob Anwendungen für Remotemanagement auf dem System installiert sind. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	system_profiler SPApplicationsDataType >> ${evidence_folder}/SYS21M20_all_installed_Apps
	
	if [[ $(cat ${evidence_folder}/SYS21M20_all_installed_Apps | grep -c "Remote Desktop:") -gt 0 ]] ; then
		cat ${evidence_folder}/SYS21M20_all_installed_Apps | sed -n '/Remote Desktop:/,/.app/p' >> ${evidence_folder}/SYS21M20_Remote_Desktop_Apps
		
		while read Remote_Desktop_Apps
		do
			printf "	%b	${Remote_Desktop_Apps} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M20_Remote_Desktop_Apps
	else
		printf "	%b	Es wurden keine installierten Anwendungen für Remotemanagement gefunden. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}		
}


################################################
# 
# SYS.2.1.M20 BSI - Apple Remote Desktop
#
###################################################

SYS21M20_ARDAgent ()
{
	printf "	%b	Überprüfe, ob Anwendungen Apple Remote Desktop auf eingehende IP4 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i4 | grep -c "ARDAgent") -gt 0 ]] ; then
		sudo lsof -i4 | grep "ARDAgent" >> ${evidence_folder}/SYS21M20_ARD_lsof_ip4
		printf "	%b	Die Anwendungen Apple Remote Desktop (ARD) lauscht auf eingehende IP4 Kommunikation. %s\\n" | tee -a ${Audit_file}
		printf "	%b	Die PID ist:  $(sudo lsof -i4 | grep "ARDAgent" | awk ' { print $2 }') %s\\n" | tee -a ${Audit_file}
		printf "	%b	ARD lauscht unter Benutzer:  $(sudo lsof -i4 | grep "ARDAgent" | awk ' { print $3 }') %s\\n" | tee -a ${Audit_file}
		printf "	%b	Der Devicename lautet:  $(sudo lsof -i4 | grep "ARDAgent" | awk ' { print $6 }') %s\\n" | tee -a ${Audit_file}
		printf "	%b	Das verwendete Protokoll basiert auf:  $(sudo lsof -i4 | grep "ARDAgent" | awk ' { print $8 }') %s\\n" | tee -a ${Audit_file}
		printf "	%b	Die Verbindungsdetails lauten:  $(sudo lsof -i4 | grep "ARDAgent" | awk ' { print $9 }') %s\\n" | tee -a ${Audit_file}
	else
		
		printf "	%b	Die Anwendungen Apple Remote Desktop lauscht nicht auf eingehende IP4 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob Anwendungen Apple Remote Desktop auf eingehende IP6 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i6 | grep -c "ARDAgent" ) -gt 0 ]] ; then
		sudo lsof -i6 | grep "ARDAgent" >> ${evidence_folder}/SYS21M20_ARD_lsof_ip6
		if [[ $(sudo lsof -i6 | grep -c "ARDAgent" | grep "UDP" ) -gt 0 ]] ; then
			printf "	%b	Die Anwendungen Apple Remote Desktop (ARD) lauscht auf eingehende IP6 UDP Kommunikation. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Die PID ist:  $(sudo lsof -i6 | grep "ARDAgent" | grep "UDP" | awk ' { print $2 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	ARD lauscht unter Benutzer:  $(sudo lsof -i6 | grep "ARDAgent" | grep "UDP" | awk ' { print $3 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Der Devicename lautet:  $(sudo lsof -i6 | grep "ARDAgent" | grep "UDP" | awk ' { print $6 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Das verwendete Protokoll basiert auf:  $(sudo lsof -i6 | grep "ARDAgent" | grep "UDP" | awk ' { print $8 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Die Verbindungsdetails lauten:  $(sudo lsof -i6 | grep "ARDAgent" | grep "UDP" | awk ' { print $9 }') %s\\n" | tee -a ${Audit_file}
		fi
		if [[ $(sudo lsof -i6 | grep -c "ARDAgent" | grep "TCP" ) -gt 0 ]] ; then
			printf "	%b	Die Anwendungen Apple Remote Desktop (ARD) lauscht auf eingehende IP6 TCP Kommunikation. %s\\n" | tee -a ${Audit_file}
			printf "	%b	Die PID ist:  $(sudo lsof -i6 | grep "ARDAgent" | grep "TCP" | awk ' { print $2 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	ARD lauscht unter Benutzer:  $(sudo lsof -i6 | grep "ARDAgent" | grep "TCP" | awk ' { print $3 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Der Devicename lautet:  $(sudo lsof -i6 | grep "ARDAgent" | grep "TCP" | awk ' { print $6 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Das verwendete Protokoll basiert auf:  $(sudo lsof -i6 | grep "ARDAgent" | grep "TCP" | awk ' { print $8 }') %s\\n" | tee -a ${Audit_file}
			printf "	%b	Die Verbindungsdetails lauten:  $(sudo lsof -i6 | grep "ARDAgent" | grep "TCP" | awk ' { print $9 }') %s\\n" | tee -a ${Audit_file}
		fi		
	else
		printf "	%b	Die Anwendungen Apple Remote Desktop lauscht nicht auf eingehende IP6 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
}


################################################
# 
# SYS.2.1.M20 BSI - SSH DenyUsers
#
###################################################

SYS21M20_SSH_Deny_Users_Groups ()

{
printf "	%b	Überprüfe die Einstellungen für \"DenyUsers\" und \"DenyGroups\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Die Anmeldung ist für Benutzernamen,die einem der Muster entsprechen, nicht zulässig. Nur Benutzernamen
		sind gültig; eine numerische Benutzer-ID wird nicht erkannt. Standardmäßig ist die Anmeldung für alle Benutzer erlaubt.
		Wenn das Muster die Form USER@HOST hat, werden USER und HOST getrennt geprüft, wodurch die Anmeldungen auf bestimmte 
		Benutzer von bestimmten Hosts beschränkt werden. HOST-Kriterien können zusätzlich Adressen enthalten, die im 
		CIDR-Adress-/Masklenformat übereinstimmen. Die allow/deny Direktiven werden in den folgenden Schritten verarbeitetlowing
		Auftrag: DenyUsers, AllowUsers, DenyGroups und schließlich AllowGroups. %s\\n" | tee -a ${Audit_file}
		
if [ -e /etc/ssh/sshd_config ]; then
	printf "	%b	Überprüfe, welche Benutzernamen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ $(cat /etc/ssh/sshd_config | grep -c "^DenyUsers") -gt 0 ]; then
		printf "	%b	Es dürfen sich nicht alle Benutzer via ssh anmelden. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Folgende Benutzernamen dürfen sich nicht via ssh anmelden: %s\\n"  | tee -a ${Audit_file}
		cat /etc/ssh/sshd_config | grep  "^DenyUsers" >> ${evidence_folder}/SYS21M20_SSH_DenyUsers
		while read SSH_Deny_Users
		do
			printf "	%b	${SSH_Deny_Users} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M20_SSH_DenyUsers
	else
		printf "	%b	Es dürften sich alle Benutzer via ssh anmelden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi

printf "\n" | tee -a ${Audit_file}

if [ -e /etc/ssh/sshd_config ]; then
	printf "	%b	Überprüfe, welche Benutzergruppen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ $(cat /etc/ssh/sshd_config | grep -c "^DenyGroups") -gt 0 ]; then
		printf "	%b	Es dürfen sich nicht alle Benutzergruppen via ssh anmelden. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Überprüfe, welche Benutzergruppen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
		printf "	%b	Folgende Benutzergruppen dürfen sich nicht via ssh anmelden: %s\\n"  | tee -a ${Audit_file}
		cat /etc/ssh/sshd_config | grep  "^DenyGroups" >> ${evidence_folder}/SYS21M21_SSH_DenyGroups
		while read SSH_Deny_Groups
		do
			printf "	%b	${SSH_Deny_Groups} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M21_SSH_DenyGroups
	else
		printf "	%b	Es dürften sich alle Benutzergruppen via ssh anmelden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}


#################################################
# 
# SYS.2.1.M20 BSI - SSH Permit Root Login
#
###################################################

SYS21M20_SSH_PermitRootLogin ()

{
printf "	%b	Überprüfe die Einstellungen für \"PermitRootLogin\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Das Argument kann yes, prohibit-password, forced-commands-only oder no sein.  Die Voreinstellung ist prohibit-password. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^PermitRootLogin") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_PermitRootLogin=`cat /etc/ssh/sshd_config | grep  "^PermitRootLogin" | awk ' { print $2 }'`
		if [[ ${VALUE_PermitRootLogin} == "yes" ]] ; then
			printf "	%b	Es ist das Argument \"yes\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_PermitRootLogin} == "forced-commands-only" ]] ; then
			printf "	%b	Es ist das Argument \"forced-commands-only\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_PermitRootLogin} == "no" ]] ; then
			printf "	%b	Es ist das Argument \"no\" gesetzt.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
        printf "	%b	Es ist die Voreinstellung \"prohibit-password\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}


################################################
# 
# SYS.2.1.M20 BSI - ssh Agent
#
###################################################

SYS21M20_SSHAgent ()
{
	printf "	%b	Überprüfe, ob ssh auf eingehende IP4 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i4 | grep "launchd" | grep -c "ssh") -gt 0 ]] ; then
		sudo lsof -i4 | grep "launchd" | grep "ssh" >> ${evidence_folder}/SYS21M20_ssh_lsof_ip4
		while read ssh_lsof_ip4
		do
			printf "	%b	${ssh_lsof_ip4} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M20_ssh_lsof_ip4
	else
		
		printf "	%b	ssh lauscht nicht auf eingehende IP4 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob ssh auf eingehende IP6 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i6 | grep "launchd" | grep -c "ssh") -gt 0 ]] ; then
		sudo lsof -i6 | grep "launchd" | grep "ssh" >> ${evidence_folder}/SYS21M20_ssh_lsof_ip6
		while read ssh_lsof_ip6
		do
			printf "	%b	${ssh_lsof_ip6} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M20_ssh_lsof_ip6
	else
		printf "	%b	ssh lauscht nicht auf eingehende IP6 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
}


################################################
# 
# SYS.2.1.M20 BSI - Apple screen sharing via VNC
#
###################################################

SYS21M20_screensharing ()
{
	printf "	%b	Überprüfe, ob der Service Screensharing via dem Launch Deamon gestartet wurde. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(launchctl list | grep -c "screensharing" ) -gt 0 ]] ; then
		launchctl list | grep screensharing  >> ${evidence_folder}/SYS21M20_launchctl_screensharing
		
	while read launchctl_screensharing
		do
			printf "	%b	${launchctl_screensharing} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M20_launchctl_screensharing
	else
		
		printf "	%b	Der Service Screensharing wurde nicht via Launch Deamon gestartet. %s\\n" | tee -a ${Audit_file}
	fi
	
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob der Service Screensharing auf eingehende IP4 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i4 | grep -c "screen" ) -gt 0 ]] ; then
		sudo lsof -i4 | grep "screen"  >> ${evidence_folder}/SYS21M20_screen_lsof_ip4
		while read screen_lsof_ip4
		do
			printf "	%b	${screen_lsof_ip4} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M20_screen_lsof_ip4
	else
		
		printf "	%b	Der Service Screensharing lauscht nicht auf eingehende IP4 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob der Service Screensharing auf eingehende IP6 Kommunikation lauscht. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	if [[ $(sudo lsof -i6 | grep -c "screen" ) -gt 0 ]] ; then
		sudo lsof -i6 | grep "screen" >> ${evidence_folder}/SYS21M20_screen_lsof_ip6
		while read screen_lsof_ip6
		do
			printf "	%b	${screen_lsof_ip6} %s\\n" | tee -a ${Audit_file}
			
		done < ${evidence_folder}/SYS21M20_screen_lsof_ip6
	else
		printf "	%b	Der Service Screensharing lauscht nicht auf eingehende IP6 Kommunikation. %s\\n" | tee -a ${Audit_file}
	fi
	printf "\n" | tee -a ${Audit_file}
	
}

SYS21M20_Remotemanagement_Apps
sleep 0.5

SYS21M20_ARDAgent
sleep 0.5

SYS21M20_SSH_Deny_Users_Groups
sleep 0.5

SYS21M20_SSH_PermitRootLogin
sleep 0.5

SYS21M20_SSHAgent
sleep 0.5

SYS21M20_screensharing
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A21 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A21 Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Der Zugriff auf Mikrofon und Kamera eines Clients SOLLTE nur durch den Benutzer selber möglich sein,
	solange er lokal am IT-System arbeitet. Wenn ein vorhandenes Mikrofon oder eine Kamera nicht genutzt
	und deren Missbrauch verhindert werden soll, SOLLTEN diese, wenn möglich, ausgeschaltet, abgedeckt,
	deaktiviert oder physikalisch vom Gerät getrennt werden. Es SOLLTE geregelt werden, wie Kameras und 
	Mikrofone in Clients genutzt und wie die Rechte vergeben werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

################################################
# 
# SYS.2.1.M21 BSI - SSH DenyUsers
#
###################################################

SYS21M21_SSH_Deny_Users_Groups ()

{
printf "	%b	Überprüfe die Einstellungen für \"DenyUsers\" und \"DenyGroups\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Die Anmeldung ist für Benutzernamen,die einem der Muster entsprechen, nicht zulässig. Nur Benutzernamen
		sind gültig; eine numerische Benutzer-ID wird nicht erkannt. Standardmäßig ist die Anmeldung für alle Benutzer erlaubt.
		Wenn das Muster die Form USER@HOST hat, werden USER und HOST getrennt geprüft, wodurch die Anmeldungen auf bestimmte 
		Benutzer von bestimmten Hosts beschränkt werden. HOST-Kriterien können zusätzlich Adressen enthalten, die im 
		CIDR-Adress-/Masklenformat übereinstimmen. Die allow/deny Direktiven werden in den folgenden Schritten verarbeitetlowing
		Auftrag: DenyUsers, AllowUsers, DenyGroups und schließlich AllowGroups. %s\\n" | tee -a ${Audit_file}
		
if [ -e /etc/ssh/sshd_config ]; then
	printf "	%b	Überprüfe, welche Benutzernamen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ $(cat /etc/ssh/sshd_config | grep -c "^DenyUsers") -gt 0 ]; then
		printf "	%b	Es dürfen sich nicht alle Benutzer via ssh anmelden. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Folgende Benutzernamen dürfen sich nicht via ssh anmelden: %s\\n"  | tee -a ${Audit_file}
		cat /etc/ssh/sshd_config | grep  "^DenyUsers" >> ${evidence_folder}/SYS21M21_SSH_DenyUsers
		while read SSH_Deny_Users
		do
			printf "	%b	${SSH_Deny_Users} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M21_SSH_DenyUsers
	else
		printf "	%b	Es dürften sich alle Benutzer via ssh anmelden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi

if [ -e /etc/ssh/sshd_config ]; then
	printf "	%b	Überprüfe, welche Benutzergruppen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ $(cat /etc/ssh/sshd_config | grep -c "^DenyGroups") -gt 0 ]; then
		printf "	%b	Es dürfen sich nicht alle Benutzergruppen via ssh anmelden. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Überprüfe, welche Benutzergruppen sich nicht via ssh anmelden dürfen. %s\\n" "${INFO}" | tee -a ${Audit_file}
		printf "	%b	Folgende Benutzergruppen dürfen sich nicht via ssh anmelden: %s\\n"  | tee -a ${Audit_file}
		cat /etc/ssh/sshd_config | grep  "^DenyGroups" >> ${evidence_folder}/SYS21M21_SSH_DenyGroups
		while read SSH_Deny_Groups
		do
			printf "	%b	${SSH_Deny_Groups} %s\\n" | tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M21_SSH_DenyGroups
	else
		printf "	%b	Es dürften sich alle Benutzergruppen via ssh anmelden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

#################################################
# 
# SYS.2.1.M21 BSI - SSH Permit Root Login
#
###################################################

SYS21M21_SSH_PermitRootLogin ()

{
printf "	%b	Überprüfe die Einstellungen für \"PermitRootLogin\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Das Argument kann yes, prohibit-password, forced-commands-only oder no sein.  Die Voreinstellung ist prohibit-password. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^PermitRootLogin") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_PermitRootLogin=`cat /etc/ssh/sshd_config | grep  "^PermitRootLogin" | awk ' { print $2 }'`
		if [[ ${VALUE_PermitRootLogin} == "yes" ]] ; then
			printf "	%b	Es ist das Argument \"yes\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_PermitRootLogin} == "forced-commands-only" ]] ; then
			printf "	%b	Es ist das Argument \"forced-commands-only\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_PermitRootLogin} == "no" ]] ; then
			printf "	%b	Es ist das Argument \"no\" gesetzt.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
        printf "	%b	Es ist die Voreinstellung \"prohibit-password\" gesetzt. Es wird empfohlen den Wert \"no\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

#################################################
# 
# SYS.2.1.M21 BSI - SSH login grace time
#
###################################################

SYS21M21_SSH_login_grace_time ()

{
printf "	%b	Überprüfe die Einstellungen für \"SSH login grace time\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^#LoginGraceTime") -gt 0 ]; then
		printf "	%b	Überprüfe, nach wieviel Sekunden der Server die Verbindung trennt, wenn sich der Benutzer nicht erfolgreich angemeldet hat. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_LoginGraceTime=`cat /etc/ssh/sshd_config | grep  "LoginGraceTime" | awk ' { print $2 }'`
		if [ ${VALUE_LoginGraceTime} != "0" ]; then
			printf "	%b	Der Server trennt die Verbindung nach ${VALUE_LoginGraceTime}, wenn sich der Benutzer nicht erfolgreich angemeldet hat. %s\\n" "${INFO}" | tee -a ${Audit_file}
			printf "	%b	Es wird empfohlen einen Wert von 30 Sekunden. %s\\n" "${INFO}" | tee -a ${Audit_file}
		else
			printf "	%b	Es ist ein Wert von 0 gesetzt, d.h. der Server trennt die Verbindung nie, wenn sich der Benutzer nicht erfolgreich angemeldet hat. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
        printf "	%b	Der Server trennt die Verbindung nach 120 Sekunden, wenn sich der Benutzer nicht 
		erfolgreich angemeldet hat. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH MaxAuthTries
#
###################################################

SYS21M21_SSH_MaxAuthTries ()

{
printf "	%b	Überprüfe die Einstellungen für \"MaxAuthTries\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Die Einstellung \"MaxAuthTries\" gibt die maximale Anzahl der zulässigen Authentifizierungsversuche pro Verbindung an.
		Sobald die Anzahl der Authentifizierungsversuche die Hälfte des hinterlegten Wertes erreicht hat, werden weitere 
		Authentifizierungsversuche protokolliert. Der Default Wert ist 6. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^MaxAuthTries") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_MaxAuthTries=`cat /etc/ssh/sshd_config | grep  "^MaxAuthTries" | awk ' { print $2 }'`
		if [[ ${VALUE_MaxAuthTries} == 6 ]] ; then
			printf "	%b	Es ist ein Wert von \"6\" derzeit konfiguriert. Es wird empfohlen einen Wert von \"3\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_MaxAuthTries} == 3 ]] ; then
			printf "	%b	Es ist ein Wert von \"4\" derzeit konfiguriert.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ ${VALUE_MaxAuthTries} -gt 0 ]]  && [[ ${VALUE_MaxAuthTries} != 3 ]] ; then
			printf "	%b	Es ist ein Wert von \"${VALUE_MaxAuthTries}\" derzeit konfiguriert. Es wird empfohlen einen Wert von \"3\" zu konfigurieren.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist ein Wert von \"6\" derzeit konfiguriert. Es wird empfohlen einen Wert von \"3\" zu konfigurieren. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}


################################################
# 
# SYS.2.1.M21 BSI - SSH ClientAliveInterval
#
###################################################

SYS21M21_SSH_ClientAliveInterval ()

{
printf "	%b	Überprüfe die Einstellungen für \"ClientAliveInterval\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Setzt ein Timeout-Intervall in Sekunden, nach dessen Ablauf, wenn keine Daten vom Client empfangen wurden,
		sshd eine Nachricht über den verschlüsselten Kanal sendet, um eine Antwort vom Client anzufordern. Die Voreinstellung
		ist 0, was bedeutet, dass diese Nachrichten nicht an den Client gesendet werden. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^ClientAliveInterval") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_ClientAliveInterval=`cat /etc/ssh/sshd_config | grep  "^ClientAliveInterval" | awk ' { print $2 }'`
		if [[ ${VALUE_ClientAliveInterval} == 900 ]] ; then
			printf "	%b	Es ist ein Wert von \"900\" derzeit konfiguriert.  %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ ${VALUE_ClientAliveInterval} -gt 0 ]]  && [[ ${VALUE_ClientAliveInterval} != 900 ]] ; then
			printf "	%b	Es ist ein Wert von \"${VALUE_ClientAliveInterval}\" derzeit konfiguriert. Es wird empfohlen einen Wert von \"900\" zu konfigurieren.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist ein Wert von \"0\" per Default konfiguriert. Es wird empfohlen einen Wert von \"900\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH ClientAliveCountMax
#
###################################################

SYS21M21_SSH_ClientAliveInterval ()

{
printf "	%b	Überprüfe die Einstellungen für \"ClientAliveCountMax\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Legt die Anzahl der Client Alive Nachrichten fest, die gesendet werden können, ohne dass sshd 
		irgendwelche Nachrichten vom Client erhält. Wenn dieser Schwellenwert erreicht wird, während Client 
		Alive-Nachrichten gesendet werden, trennt sshd den Client und beendet die Sitzung. Es ist wichtig 
		zu beachten, dass sich die Verwendung von Client-Alive-Nachrichten stark von TCPKeepAlive unterscheidet.
		Die Client Alive-Nachrichten werden über den verschlüsselten Kanal gesendet und sind daher nicht spooffähig.
		Die von TCPKeepAlive aktivierte Option TCP keepalive ist spoofable.  Der Client Alive-Mechanismus ist wertvoll,
		wenn der Client oder Server darauf angewiesen ist, zu wissen, wann eine Verbindung inaktiv geworden ist.
	
		Der Standardwert ist 3, wenn ClientAliveInterval auf 15 gesetzt ist und ClientAliveCountMax auf dem Standardwert
		belassen wird, wird der nicht reagierende SSH-Clients nach ca. 45 Sekunden getrennt. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^ClientAliveCountMax") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_ClientAliveCountMax=`cat /etc/ssh/sshd_config | grep  "^ClientAliveCountMax" | awk ' { print $2 }'`
		if [[ ${VALUE_ClientAliveCountMax} == 3 ]] ; then
			printf "	%b	Es ist ein Wert von \"3\" derzeit konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
			einen Wert von \"900\" zu hinterlegen. %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ ${VALUE_ClientAliveCountMax} -gt 0 ]]  && [[ ${VALUE_ClientAliveCountMax} != 3 ]] ; then
			printf "	%b	Es ist ein Wert von \"${VALUE_ClientAliveCountMax}\" derzeit konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
			einen Wert von \"0\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist ein Wert von \"3\" per Default konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
		einen Wert von \"0\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH ClientAliveCountMax
#
###################################################

SYS21M21_SSH_ChallengeResponseAuthentication ()

{
printf "	%b	Überprüfe die Einstellungen für \"ChallengeResponseAuthentication\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Gibt an, ob die Challenge-Response-Authentifizierung erlaubt ist z.B. über PAM oder über Authentisierungsstile, 
		die in login.conf unterstützt werden. Der Standard ist yes. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^ChallengeResponseAuthentication") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_ChallengeResponseAuthentication=`cat /etc/ssh/sshd_config | grep  "^ChallengeResponseAuthentication" | awk ' { print $2 }'`
		if [[ ${VALUE_ChallengeResponseAuthentication} == "yes" ]] ; then
			printf "	%b	Es ist der Wert  \"yes\" derzeit konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
			einen Wert \"no\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_ChallengeResponseAuthentication} == "no" ]] ; then
			printf "	%b	Es ist der Wert \"no\" derzeit konfiguriert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist der Wert \"yes\" per Default konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
		einen Wert von \"no\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH ClientAliveCountMax
#
###################################################

SYS21M21_SSH_PubkeyAuthentication ()

{
printf "	%b	Überprüfe die Einstellungen für \"PubkeyAuthentication\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Gibt an, ob die Authentisierung mit öffentlichem Schlüssel erlaubt ist. Die Voreinstellung ist yes. %s\\n" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^PubkeyAuthentication") -gt 0 ]; then
		printf "	%b	Überprüfe, welches Argument händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_PubkeyAuthentication=`cat /etc/ssh/sshd_config | grep  "^PubkeyAuthentication" | awk ' { print $2 }'`
		if [[ ${VALUE_PubkeyAuthentication} == "yes" ]] ; then
			printf "	%b	Es ist der Wert  \"yes\" derzeit konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
			einen Wert \"no\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_PubkeyAuthentication} == "no" ]] ; then
			printf "	%b	Es ist der Wert \"no\" derzeit konfiguriert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist der Wert \"yes\" per Default konfiguriert. Es wird empfohlen bei hohen bzw. sehr hohen Schutzbedarf 
		einen Wert von \"no\" zu hinterlegen. %s\\n" "${CROSS}" | tee -a ${Audit_file}
    fi
fi
printf "\n" | tee -a ${Audit_file}
}


################################################
# 
# SYS.2.1.M21 BSI - SSH Ciphers
#
###################################################

SYS21M21_SSH_Ciphers ()

{
printf "	%b	Überprüfe die Einstellungen für \"Ciphers\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Gibt die zulässigen Ciphers an.  Mehrere Cipher müssen durch Komma getrennt sein. Wenn der 
		angegebene Wert mit einem'+'-Zeichen beginnt, werden die angegebenen Ziffern an den Standardsatz angehängt,
		anstatt sie zu ersetzen. Wenn der angegebene Wert mit einem'-'-Zeichen beginnt, werden die angegebenen 
		Chiffren (einschließlich Wildcards) aus dem Standardsatz entfernt, anstatt sie zu ersetzen. %s\\n" | tee -a ${Audit_file}

printf "	%b	Überprüfe, welche Ciphers unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
ssh -Q cipher >> ${evidence_folder}/SYS21M21_SSH_Cipher
printf "	%b	Folgende Cipher werden unterstützt: %s\\n"  | tee -a ${Audit_file}
while read SSH_Ciphers
do
		printf "	%b		${SSH_Ciphers} %s\\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M21_SSH_Cipher

printf "	%b	Überprüfe, ob nicht mehr empfohlen Ciphers weiterhin unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^Ciphers") -gt 0 ]; then
		printf "	%b	Es sind Anpassungen an den per Standard hinterlegten Cipher vorgenommen worden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		local VALUE_Ciphers=`cat /etc/ssh/sshd_config | grep  "^Ciphers" | awk ' { print $2 }'`
		cat /etc/ssh/sshd_config | grep  "^Ciphers" >> ${evidence_folder}/SYS21M21_SSH_Non_Default_Cipher
		printf "	%b	Bitte händisch prüfen, dass nur diese Gruppe \"aes128-ctr,aes192-ctr,aes256-ctr\" verwendet wird. %s\\n" | tee -a ${Audit_file}
	else
		printf "	%b	Es sind alle im Standard hinterlegten Cipher verwendbar. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Folgende Cipher sind im Standard hinterlegt: %s\\n"  | tee -a ${Audit_file}
		printf "	%b		chacha20-poly1305@openssh.com %s\\n"  | tee -a ${Audit_file}
        printf "	%b		aes128-ctr,aes192-ctr,aes256-ctr %s\\n"  | tee -a ${Audit_file}
        printf "	%b		aes128-gcm@openssh.com,aes256-gcm@openssh.com %s\\n"  | tee -a ${Audit_file}
		printf "	%b	Es sollte nur diese Gruppe \"aes128-ctr,aes192-ctr,aes256-ctr\" verwendet werden. %s\\n" | tee -a ${Audit_file}
    fi
fi

printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH MACs
#
###################################################

SYS21M21_SSH_MACs ()

{
printf "	%b	Überprüfe die Einstellungen für \"MACs\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Gibt die verfügbaren MAC-Algorithmen (Message Authentication Code) an. Der MAC-Algorithmus 
		wird zum Schutz der Datenintegrität verwendet.  Mehrere Algorithmen müssen durch Komma getrennt sein.
		Wenn der angegebene Wert mit einem'+'-Zeichen beginnt, werden die angegebenen Algorithmen an den 
		Standardsatz angehängt, anstatt sie zu ersetzen. Wenn der angegebene Wert mit einem'-'-Zeichen beginnt, 
		werden die angegebenen Algorithmen (einschließlich Wildcards) aus dem Standardsatz entfernt, anstatt sie zu ersetzen. %s\\n" | tee -a ${Audit_file}

printf "	%b	Überprüfe, welche MAC-Algorithmen unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
ssh -Q mac >> ${evidence_folder}/SYS21M21_SSH_MAcs
printf "	%b	Folgende MAC-Algorithmen werden unterstützt: %s\\n"  | tee -a ${Audit_file}
while read SSH_MACs
do
		printf "	%b		${SSH_MACs} %s\\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M21_SSH_MAcs

printf "	%b	Überprüfe, ob nicht mehr empfohlen MAC-Algorithmen weiterhin unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^MACs") -gt 0 ]; then
		printf "	%b	Es sind Anpassungen an den per Standard hinterlegten MAC-Algorithmen vorgenommen worden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		local VALUE_MACs=`cat /etc/ssh/sshd_config | grep  "^MACs" | awk ' { print $2 }'`
		cat /etc/ssh/sshd_config | grep  "^MACs" >> ${evidence_folder}/SYS21M21_SSH_Non_Default_MACs
		printf "	%b	Bitte händisch prüfen, dass nur diese Gruppe \"hmac-sha2-256,hmac-sha2-512\" verwendet wird. %s\\n" | tee -a ${Audit_file}
	else
		printf "	%b	Es sind alle im Standard hinterlegten MAC-Algorithmen verwendbar. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Folgende MAC-Algorithmen sind im Standard hinterlegt: %s\\n"  | tee -a ${Audit_file}
		printf "	%b		umac-64-etm@openssh.com,umac-128-etm@openssh.com %s\\n"  | tee -a ${Audit_file}
        printf "	%b		hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com %s\\n"  | tee -a ${Audit_file}
        printf "	%b		hmac-sha1-etm@openssh.com %s\\n"  | tee -a ${Audit_file}
        printf "	%b		umac-64@openssh.com,umac-128@openssh.com %s\\n"  | tee -a ${Audit_file}
        printf "	%b		hmac-sha2-256,hmac-sha2-512,hmac-sha1 %s\\n"  | tee -a ${Audit_file}
		printf "	%b	Es sollte nur diese Gruppe \"hmac-sha2-256,hmac-sha2-512\" verwendet werden. %s\\n" | tee -a ${Audit_file}
    fi
fi

printf "\n" | tee -a ${Audit_file}
}

################################################
# 
# SYS.2.1.M21 BSI - SSH KexAlgorithms 
#
###################################################

SYS21M21_SSH_KexAlgorithms ()

{
printf "	%b	Überprüfe die Einstellungen für \"KexAlgorithms\" in der ssh Konfiguration. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Gibt die verfügbaren KEX (Key Exchange)-Algorithmen an. Mehrere Algorithmen müssen durch Komma getrennt sein.
		Wenn der angegebene Wert mit einem'+'-Zeichen beginnt, werden die angegebenen Algorithmen an den 
		Standardsatz angehängt, anstatt sie zu ersetzen. Wenn der angegebene Wert mit einem'-'-Zeichen beginnt, 
		werden die angegebenen Algorithmen (einschließlich Wildcards) aus dem Standardsatz entfernt, anstatt sie zu ersetzen. %s\\n" | tee -a ${Audit_file}

printf "	%b	Überprüfe, welche KEX (Key Exchange)-Algorithmen unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
ssh -Q kex >> ${evidence_folder}/SYS21M21_SSH_KexAlgorithms
printf "	%b	Folgende KEX (Key Exchange)-Algorithmen werden unterstützt: %s\\n"  | tee -a ${Audit_file}
while read SSH_KexAlgorithms
do
		printf "	%b		${SSH_KexAlgorithms} %s\\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M21_SSH_KexAlgorithms

printf "	%b	Überprüfe, ob nicht mehr empfohlen KEX (Key Exchange)-Algorithmen weiterhin unterstützt werden. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /etc/ssh/sshd_config ]; then
	if [ $(cat /etc/ssh/sshd_config | grep -c "^KexAlgorithms") -gt 0 ]; then
		printf "	%b	Es sind Anpassungen an den per Standard hinterlegten KEX (Key Exchange)-Algorithmen vorgenommen worden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		local VALUE_KexAlgorithms=`cat /etc/ssh/sshd_config | grep  "^KexAlgorithms" | awk ' { print $2 }'`
		cat /etc/ssh/sshd_config | grep  "^MACs" >> ${evidence_folder}/SYS21M21_SSH_Non_Default_KexAlgorithms
		printf "	%b	Bitte händisch prüfen, dass nur diese Gruppe \"diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\" verwendet wird. %s\\n" | tee -a ${Audit_file}
	else
		printf "	%b	Es sind alle im Standard hinterlegten KEX (Key Exchange)-Algorithmen verwendbar. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Folgende MAC-Algorithmen sind im Standard hinterlegt: %s\\n"  | tee -a ${Audit_file}
		printf "	%b		curve25519-sha256,curve25519-sha256@libssh.org %s\\n"  | tee -a ${Audit_file}
        printf "	%b		ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521, %s\\n"  | tee -a ${Audit_file}
        printf "	%b		diffie-hellman-group-exchange-sha256 %s\\n"  | tee -a ${Audit_file}
        printf "	%b		diffie-hellman-group16-sha512,diffie-hellman-group18-sha512 %s\\n"  | tee -a ${Audit_file}
        printf "	%b		diffie-hellman-group14-sha256,diffie-hellman-group14-sha1 %s\\n"  | tee -a ${Audit_file}
		printf "	%b	Es sollte nur diese Gruppe angewandt werden 
		\"diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521\". %s\\n" | tee -a ${Audit_file}
    fi
fi

printf "\n" | tee -a ${Audit_file}
}


SYS21M21_SSH_Deny_Users_Groups
sleep 0.5

SYS21M21_SSH_PermitRootLogin
sleep 0.5

SYS21M21_SSH_login_grace_time
sleep 0.5

SYS21M21_SSH_MaxAuthTries
sleep 0.5

SYS21M21_SSH_ClientAliveInterval
sleep 0.5

SYS21M21_SSH_ChallengeResponseAuthentication
sleep 0.5

SYS21M21_SSH_PubkeyAuthentication
sleep 0.5

SYS21M21_SSH_Ciphers
sleep 0.5

SYS21M21_SSH_MACs
sleep 0.5

SYS21M21_SSH_KexAlgorithms
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A22 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A22 Abmelden nach Aufgabenerfüllung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTEN alle Benutzer verpflichtet werden, sich nach Aufgabenerfüllung vom IT-System bzw. von der
	IT-Anwendung abzumelden, vor allem bei Nutzung eines Systems durch mehrere Benutzer. Ist für einen 
	Benutzer absehbar, dass nur eine kurze Unterbrechung der Arbeit erforderlich ist, SOLLTE er die 
	Bildschirmsperre aktivieren, statt sich abzumelden. Wenn technisch möglich, SOLLTE die Bildschirmsperre 
	nach längerer Inaktivität automatisch aktiviert bzw. der Benutzer automatisch abgemeldet werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M22_AutoLogOutDelay ()

{
	printf "	%b	Überprüfe die aktuelle Einstellungen für das \"AutoLogOutDelay\". %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ $(defaults read /Library/Preferences/.GlobalPreferences | grep -c "com.apple.autologout.AutoLogOutDelay") -gt 0 ]; then
		printf "	%b	Überprüfe, welcher Wert händisch gesetzt wurde. %s\\n" "${INFO}" | tee -a ${Audit_file}
		local VALUE_AutoLogOutDelay=`defaults read /Library/Preferences/.GlobalPreferences | grep "com.apple.autologout.AutoLogOutDelay"| awk ' { print $3 }' | sed "s/;//"`
		if [[ ${VALUE_AutoLogOutDelay} -gt 0 ]] && [[ ${VALUE_AutoLogOutDelay} -lt 3601 ]] ; then
			printf "	%b	Es ist ein Wert von \"${VALUE_AutoLogOutDelay}\" Sekunden derzeit konfiguriert. %s\\n" "${TICK}" | tee -a ${Audit_file}
		elif [[ ${VALUE_AutoLogOutDelay} -gt 3600 ]] ; then
			printf "	%b	Es ist ein Wert von \"${VALUE_AutoLogOutDelay}\" Sekunden derzeit konfiguriert. Es sollte maximal 3600 Sekunden konfiguriert werden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		elif [[ ${VALUE_AutoLogOutDelay} == 0 ]] ; then	
			printf "	%b	Es ist ein Wert von \"${VALUE_AutoLogOutDelay}\" Sekunden derzeit konfiguriert. Dies bedeutet die Funktion Auto Logout ist deaktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Es ist kein Wert derzeit konfiguriert. Dies bedeutet die Funktion Auto Logout ist deaktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
	printf "\n"| tee -a ${Audit_file}
	
}

SYS21M22_AutoLogOutDelay
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A23 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A23 Nutzung von Client-Server-Diensten %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Wenn möglich, SOLLTEN zum Informationsaustausch dedizierte Serverdienste genutzt und direkte Verbindungen
	zwischen Clients vermieden werden. Falls dies nicht möglich ist, SOLLTE festgelegt werden, welche 
	Client-zu-Client-Dienste genutzt und welche Informationen darüber ausgetauscht werden dürfen. Wenn 
	erforderlich, SOLLTEN die Benutzer für die Nutzung solcher Dienste geschult werden. Direkte Verbindungen 
	zwischen Clients SOLLTEN sich nur auf das LAN beschränken. Auto-Discovery-Protokolle SOLLTEN auf das 
	notwendige Maß beschränkt werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M23_AirDrop ()
{

while read User_gt_500
do
printf "	%b	Überprüfe, ob AirDrop für das Benutzerkonto ${User_gt_500} aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist ]; then
	
	defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist >> ${evidence_folder}/SYS21M23_AirDrop
	local dict_exists=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist 2> /dev/null| grep -c "DisableAirDrop"`
	if [ $dict_exists == 1 ]; then
		printf "	%b	Für das Benutzerkonto ${User_gt_500} wird der Test durchgeführt  %s\\n" | tee -a ${Audit_file}
			printf "	%b	Für den Benutzer ${User_gt_500} ist AirDrop aktiv %s\\n" "${CROSS}"	| tee -a ${Audit_file}
			
   		else
			printf "	%b	Für den Benutzer ${User_gt_500} ist die Einstellung für AirDrop nicht gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
        fi
	else
	printf "	%b	Die Einstellung für AirDrop ist für den Benutzer ${User_gt_500} global nicht vorhanden und somit ist AirDrop nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
fi 
printf "\n" | tee -a ${Audit_file}
done < ${Audit_folder}/TMP_User_List_gt_500

}

SYS21M23_NoMulticastAdvertisements ()
{
	printf "	%b	Überprüfe, ob Bonjour advertising aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ -e /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist ]; then
		defaults read /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist >> ${evidence_folder}/SYS21M23_MulticastAdvertisements
		local  Value_NoMulticastAdvertisements=`defaults read /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist | grep -c "NoMulticastAdvertisements"`
		if [ "${Value_NoMulticastAdvertisements}" -gt 0 ]; then
			printf "	%b	Bonjour advertising ist nicht aktiv. %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Bonjour advertising ist aktiv. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
		printf "	%b	Bonjour advertising ist aktiv. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
}

SYS21M23_access_screensharing ()
{
	printf "	%b	Überprüfe, ob Screensharing aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
	if [ -e /private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist ]; then
		defaults read /private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist >> ${evidence_folder}/SYS21M23_access_screensharing
		local  Value_screensharing_user=`sudo defaults read /private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist | grep -c "users"`
		local  Value_screensharing_groupmember=`sudo defaults read /private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist | grep -c "groupmember"`
		local  Value_screensharing_nestedgroups=`sudo defaults read /private/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist | grep -c "nestedgroups"`
				
		if [ "${Value_screensharing_nestedgroups}" -gt 0 ]; then
				# CCE_79488_3_restrict_screen_sharing_to_specified_users
				printf "	%b	coming soon. %s\\n" "${CROSS}" | tee -a ${Audit_file}
				NESTEDGROUPS=`sudo defaults read pivate/var/db/dslocal/nodes/Default/groups/com.apple.access_screensharing.plist | grep -A1 "nestedgroups" | sed -n '/"/,/"/p'| sed 's/"//g'`
				dsmemberutil getid -X ${NESTEDGROUPS}
			else
				printf "	%b	Es wurde kein Wert für \"nestedgroups\" gefunden. %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
	else
		printf "	%b	coming soon. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
}

SYS21M23_iCloud ()
{
while read User_gt_500
do
printf "	%b	Überprüfe, ob iCloud global für den Benutzer ${User_gt_500} aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
if [ -e /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist ]; then
	defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist 2> /dev/null >> ${evidence_folder}/SYS24M8_iCloud
	local dict_exists=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist 2> /dev/null | sed -n '/Accounts/,/(/p' | grep "AccountID" | awk ' { print $3 }' | sed 's/;//' | wc -l`
	if [ ${dict_exists} == 1 ]; then
		printf "	%b	Für den Benutzer ${User_gt_500} ist iCloud konfiguriert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		local iCloud_Account_Description=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountDescription" | awk ' { print $3 }' | sed 's/;//'` 
		local iCloud_Account_ID=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountID" | awk ' { print $3 }' | sed 's/;//'`
		local iCloud_Display_Name=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "DisplayName" | awk ' { print $3 " "$4 }' | sed 's/;//'`
		local iCloud_Account_UUID=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountUUID" | awk ' { print $3 }' | sed 's/;//'`
		local iCloud_Logged_In=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "LoggedIn" | awk ' { print $3 }' | sed 's/;//'`
		
		printf "	%b	Folgende Benutzerwerte sind hinterlegt %s\\n" "${INFO}" | tee -a ${Audit_file}
		printf "	%b		Display Name: $iCloud_Display_Name %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account Description: $iCloud_Account_Description %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account ID: $iCloud_Account_ID %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account UUID: $iCloud_Account_UUID %s\\n" | tee -a ${Audit_file}
		
		if [ ${dict_exists} == 1 ]; then
			printf "	%b		Login: aktiv %s\\n" | tee -a ${Audit_file}
		else 
			printf "	%b		Login: inaktiv %s\\n" | tee -a ${Audit_file}
		fi
	fi
else
	printf "	%b	iCloud ist global für den Benutzer ${User_gt_500} nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
	
fi
done < ${Audit_folder}/TMP_User_List_gt_500

printf "\n" | tee -a ${Audit_file}
}

SYS21M23_getsmbsettings ()
{

printf "	%b	Überprüfe die aktuellen Einstellung des SMB-Servers. %s\\n" "${INFO}" | tee -a ${Audit_file}
defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server 2> /dev/null >> ${evidence_folder}/SYS21M23_getsmbserversettings
if [[ $(cat ${evidence_folder}/SYS21M23_getsmbserversettings | grep -c "NetBIOSName") == 1 ]] ; then
NetBIOSName=`cat ${evidence_folder}/SYS21M23_getsmbserversettings | grep "NetBIOSName"| awk ' { print $3 }' | sed 's/;//'`
printf "	%b	Der NetBIOS Name des lokalen SMB Servers lautet: ${NetBIOSName} %s\\n" | tee -a ${Audit_file}
fi

if [[ $(cat ${evidence_folder}/SYS21M23_getsmbserversettings | grep -c "ServerDescription") == 1 ]] ; then
ServerDescription=`cat ${evidence_folder}/SYS21M23_getsmbserversettings | grep "ServerDescription"| awk ' { print $3 }' | sed 's/;//'`
printf "	%b	Die Beschreibung des lokalen SMB Servers lautet: ${ServerDescription} %s\\n" | tee -a ${Audit_file}
fi

printf "\n"| tee -a ${Audit_file}

printf "	%b	Überprüfe, auf welche eingehende Kommunikation gewartet und welcher Service dahinterliegt. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
sudo lsof -iTCP -sTCP:LISTEN -n -P >> ${evidence_folder}/SYS21M23_TCP_LISTEN
printf "	%b	Das System horcht auf folgende eingehende Verbindungen. %s\\n" | tee -a ${Audit_file}
while read TCP_LISTEN
	do
		printf "	%b		${TCP_LISTEN} %s\\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M23_TCP_LISTEN

printf "\n"| tee -a ${Audit_file}

while read USER_nsmb_conf
	do
		printf "	%b	Überprüfe die aktuellen Einstellungen der SMB-Client Konfiguration für Benutzer: ${USER_nsmb_conf}. %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [[ -e /Users/${USER_nsmb_conf}/Library/Preferences/nsmb.conf ]]; then
			cat /Users/${USER_nsmb_conf}/Library/Preferences/nsmb.conf >> ${evidence_folder}/SYS21M23_${USER_nsmb_conf}_nsmb_conf
			while read nsmb_conf
			do
				printf "	%b	Für den Benutzer: ${USER_nsmb_conf} wurden folgende SMB-Client Konfiguration gesichert. %s\\n" "${INFO}" | tee -a ${Audit_file}
				printf "	%b		${nsmb_conf} %s\\n" | tee -a ${Audit_file}

			done < ${evidence_folder}/SYS21M23_${USER_nsmb_conf}_nsmb_conf
			
		else
			printf "	%b	Für den Benutzer ${USER_nsmb_conf} konnten keine SMB-Client Konfiguration emittelt werden. %s\\n" | tee -a ${Audit_file}
		fi
	done < ${Audit_folder}/TMP_User_List_gt_500

printf "\n" | tee -a ${Audit_file}

printf "	%b	Überprüfe die aktuellen globalen Einstellung der SMB-Client Konfiguration: %s\\n" "${INFO}" | tee -a ${Audit_file}
if [[ -e /private/etc/nsmb.conf ]]; then
	cat /private/etc/nsmb.conf >> ${evidence_folder}/SYS21M23_global_nsmb_conf
	while read global_nsmb_conf
	do
		printf "	%b		${global_nsmb_conf} %s\\n" | tee -a ${Audit_file}
	done < ${evidence_folder}/SYS21M23_global_nsmb_conf
else
	printf "	%b	Es wurden keine Datei nsmb.conf im Pfad /private/etc/ vorgefunden somit sind folgende Default-Einstellungen aktiv: %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "	%b		[default] %s\\n" | tee -a ${Audit_file}
	printf "	%b		nbtimeout = 1s %s\\n" | tee -a ${Audit_file}
	printf "	%b		minauth = NTLMv2 %s\\n" | tee -a ${Audit_file}
	printf "	%b		port445 = normal %s\\n" | tee -a ${Audit_file}	
	printf "	%b		streams = yes %s\\n" | tee -a ${Audit_file}
	printf "	%b		notify_off = no %s\\n" | tee -a ${Audit_file}
	printf "	%b		kloglevel = 0 %s\\n" | tee -a ${Audit_file}
	printf "	%b		protocol_vers_map = 7 (SMB 1/2/3 should be enabled) %s\\n" | tee -a ${Audit_file}	
	printf "	%b		signing_required = yes %s\\n" | tee -a ${Audit_file}
	printf "	%b		signing_req_vers = 6 (SMB 2/3 should be enabled) %s\\n" | tee -a ${Audit_file}
	printf "	%b		validate_neg_off = no %s\\n" | tee -a ${Audit_file}
	printf "	%b		max_resp_timeout = 30s %s\\n" | tee -a ${Audit_file}	
	printf "	%b		submounts_off = no %s\\n" | tee -a ${Audit_file}
	printf "	%b		read_async_cnt = 4 %s\\n" | tee -a ${Audit_file}
	printf "	%b		write_async_cnt = 4 %s\\n" | tee -a ${Audit_file}
	printf "	%b		dir_cache_async_cnt = 10 %s\\n" | tee -a ${Audit_file}
	printf "	%b		dir_cache_max_cnt = 2048 %s\\n" | tee -a ${Audit_file}
	printf "	%b		dir_cache_max = 60s %s\\n" | tee -a ${Audit_file}	
	printf "	%b		dir_cache_min = 30s %s\\n" | tee -a ${Audit_file}	
	

fi
printf "\n" | tee -a ${Audit_file}

printf "	%b	Im Abschnitt [default] sollten folgende globale Einstellungen hinterlegt sein. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "	%b		[default] %s\\n" | tee -a ${Audit_file}
	printf "	%b		protocol_vers_map=4 %s\\n" | tee -a ${Audit_file}
	printf "	%b		signing_req_vers=4 %s\\n" | tee -a ${Audit_file}
	printf "	%b		signing_required=yes %s\\n" | tee -a ${Audit_file}
	printf "	%b		minauth=ntlmv2 %s\\n" | tee -a ${Audit_file}
	printf "	%b		notify_off=yes %s\\n" | tee -a ${Audit_file}
	printf "	%b		port445=no_netbios %s\\n" | tee -a ${Audit_file}
	printf "	%b		unix extensions=no %s\\n" | tee -a ${Audit_file}
	printf "	%b		veto files = /._*/.DS_Store/ %s\\n" | tee -a ${Audit_file}
printf "\n" | tee -a ${Audit_file}	

}

SYS21M23_getsmbsettings
sleep 0.5

SYS21M23_AirDrop
sleep 0.5

SYS21M23_NoMulticastAdvertisements
sleep 0.5

SYS21M23_access_screensharing
sleep 0.5

SYS21M23_iCloud
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A24 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A24 Umgang mit Wechseldatenträgern im laufenden System %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE verhindert werden, dass auf Clients von Laufwerken oder über Schnittstellen unkontrolliert
	Software installiert oder unberechtigt Daten kopiert werden können. Auf die Schnittstellen SOLLTE NUR 
	restriktiv zugegriffen werden können. Es SOLLTE generell verhindert werden, dass von den Clients auf 
	Daten oder Wechseldatenträgern aus nicht vertrauenswürdigen Quellen zugegriffen wird." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M24 ()

{

printf "	%b	Überprüfe, ob via Profilmanager das System ${MODELIDENTIFIER} verwaltet wird.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(system_profiler SPConfigurationProfileDataType | wc -l) -gt 0 ] ; then
	system_profiler SPConfigurationProfileDataType >> ${evidence_folder}/SYS21M24_SPConfigurationProfileDataType
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then
	defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist >> ${evidence_folder}/SYS21M24_com_apple_systemuiserver_plist
	fi
	
	printf "	%b	Das System ${MODELIDENTIFIER} wird mittels Profilen verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	printf "\n" | tee -a ${Audit_file}
	printf "	%b	Überprüfe, ob via Profil Zugriffeinstellungen für Festplattenmedien (interne und externe Laufwerke, Images und DVD-Ram) installiert sind  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	#################################################
	# 
	# interne Laufwerke
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für die interne Festplatte vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_harddisk_internal=`system_profiler SPConfigurationProfileDataType | grep -c "harddisk-internal"`
	if [ ${profiles_harddisk_internal} -gt 1 ] ; then
		printf "	%b	Einstellungen für interne Festplatten werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	elif [ ${profiles_harddisk_internal} == 1 ] ; then
		printf "	%b	Einstellungen für interne Festplatten werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Einstellungen für interne Festplatten werden von keinem Profile vorgegeben. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
	fi
		
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then
		printf "	%b	Überprüfe die Einstellungen für interne Festplatten (erlauben, mit Authentisierung oder nur Lesen)  %s\\n" "${INFO}" | tee -a ${Audit_file}
		local harddisk_internal_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-internal/,/);/p' | grep -c "deny"`
		if [ ${harddisk_internal_deny} == 1 ] ; then
			printf "	%b	interne Festplatten dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
	
		else	
	
			local harddisk_internal_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-internal/,/);/p' | grep -c "authenticate"`
			if [ ${harddisk_internal_authenticate} == 1 ] ; then
				printf "	%b	interne Festplatten dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	interne Festplatten dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
		
		local harddisk_internal_read_only=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-internal/,/);/p' | grep -c "read-only"`
		if [ ${harddisk_internal_read_only} == 1 ] ; then
			printf "	%b	interne Festplatten dürfen nur lesend verwendet werden %s\\n"  | tee -a ${Audit_file}
		fi
	
	fi	
fi
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# externe Laufwerke
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für die externe Festplatte vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_harddisk_external=`system_profiler SPConfigurationProfileDataType | grep -c "harddisk-external"`
	if [ ${profiles_harddisk_external} -gt 1 ] ; then
		printf "	%b	Einstellungen für externe Festplatten werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	elif [ ${profiles_harddisk_external} == 1 ] ; then
		printf "	%b	Einstellungen für externe Festplatten werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}	
	
	else
		printf "	%b	Einstellungen für externe Festplatten werden von keinem Profile vorgegeben. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}	
	fi
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then	
		printf "	%b	Überprüfe die Einstellungen für externe Festplatten (erlauben, mit Authentisierung oder nur Lesen)  %s\\n" "${INFO}" | tee -a ${Audit_file}
		
		local harddisk_external_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-external/,/);/p' | grep -c "deny"`
		if [ ${harddisk_external_deny} == 1 ] ; then
			printf "	%b	externe Festplatten dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
	
		else
		
			local harddisk_external_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-external/,/);/p' | grep -c "authenticate"`
			if [ ${harddisk_external_authenticate} == 1 ] ; then
				printf "	%b	externe Festplatten dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	externe Festplatten dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
	
			local harddisk_external_read_only=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/harddisk-external/,/);/p' | grep -c "read-only"`
			if [ ${harddisk_external_read_only} == 1 ] ; then
			printf "	%b	externe Festplatten dürfen nur lesend verwendet werden %s\\n"  | tee -a ${Audit_file}
			fi
		fi	
	fi	
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# Disk Images
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für Disk-Images vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_disk_image=`system_profiler SPConfigurationProfileDataType | grep -c "disk-image"`
	if [ ${profiles_disk_image} -gt 1 ] ; then
		printf "	%b	Einstellungen für Disk-Images werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für Disk-Images werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für Disk-Images (erlauben, mit Authentisierung oder nur Lesen)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then	
		local disk_image_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/disk-image/,/);/p' | grep -c "deny"`
		if [ ${disk_image_deny} == 1 ] ; then
			printf "	%b	Disk-Images dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
			
		else
		
			local disk_image_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/disk-image/,/);/p' | grep -c "authenticate"`
			if [ ${disk_image_authenticate} == 1 ] ; then
				printf "	%b	Disk-Images dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	Disk-Images dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
	
			local disk_image_read_only=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/disk-image/,/);/p' | grep -c "read-only"`
			if [ ${disk_image_read_only} == 1 ] ; then
				printf "	%b	Disk-Images dürfen nur lesend verwendet werden %s\\n"  | tee -a ${Audit_file}
			fi
		fi		
	fi	
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# DVD-RAM
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für DVD-RAMs vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_dvdram=`system_profiler SPConfigurationProfileDataType | grep -c "dvdram"`
	if [ ${profiles_dvdram} -gt 1 ] ; then
		printf "	%b	Einstellungen für DVD-RAMs werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für DVD-RAMs werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für DVD-RAMs (erlauben, mit Authentisierung oder nur Lesen)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then		
		local dvdram_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/dvdram/,/);/p' | grep -c "deny"`
		if [ ${dvdram_deny} == 1 ] ; then
			printf "	%b	DVD-RAMs dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
		
		else
		
			local dvdram_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/dvdram/,/);/p' | grep -c "authenticate"`
			if [ ${dvdram_authenticate} == 1 ] ; then
				printf "	%b	DVD-RAMs dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	DVD-RAMs dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
	
			local dvdram_read_only=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/dvdram/,/);/p' | grep -c "read-only"`
			if [ ${dvdram_read_only} == 1 ] ; then
				printf "	%b	DVD-RAMs dürfen nur lesend verwendet werden %s\\n"  | tee -a ${Audit_file}
			fi		
		fi
	fi	
	
	printf "\n" | tee -a ${Audit_file}
	printf "\n" | tee -a ${Audit_file}
	
	printf "	%b	Überprüfe, ob via Profil Zugriffeinstellungen für Wechselmedien (CDs, CD-ROMS, DVDs und beschreibbare Medien) installiert sind  %s\\n" "${INFO}" | tee -a ${Audit_file}
	#################################################
	# 
	# CDs und CD-ROMs
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für CDs und CD-ROMs vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_cd=`system_profiler SPConfigurationProfileDataType | grep -v "blankcd =" | grep -c "cd ="`
	if [ ${profiles_cd} -gt 1 ] ; then
		printf "	%b	Einstellungen für CDs und CD-ROMs werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für CDs und CD-ROMs werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für CDs und CD-ROMs (erlauben und mit Authentisierung)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then		
		local cd_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | grep -v "blankcd =" | sed -n '/cd =/,/);/p' | grep -c "deny"`
		if [ ${cd_deny} == 1 ] ; then
			printf "	%b	CDs und CD-ROMs dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
	
		else
		
			local cd_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | grep -v "blankcd =" | sed -n '/cd =/,/);/p' | grep -c "authenticate"`
			if [ ${cd_authenticate} == 1 ] ; then
				printf "	%b	CDs und CD-ROMs dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	CDs und CD-ROMs dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
	fi
	printf "\n" | tee -a ${Audit_file}
	#################################################
	# 
	# DVDs
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für DVDs vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_dvd=`system_profiler SPConfigurationProfileDataType | grep -v "blankdvd =" | grep -c "dvd ="`
	if [ ${profiles_dvd} -gt 1 ] ; then
		printf "	%b	Einstellungen für DVDs werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für DVDs werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für DVDs (erlauben und mit Authentisierung)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then		
		local dvd_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | grep -v "blankdvd =" | sed -n '/dvd =/,/);/p' | grep -c "deny"`
		if [ ${dvd_deny} == 1 ] ; then
			printf "	%b	DVDs dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
			
		else
		
			local dvd_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | grep -v "blankdvd =" | sed -n '/dvd =/,/);/p' | grep -c "authenticate"`
			if [ ${dvd_authenticate} == 1 ] ; then
				printf "	%b	DVDs dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	DVDs dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
	fi
	printf "\n" | tee -a ${Audit_file}

	#################################################
	# 
	# leere CD
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für leer CDs vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_blankcd=`system_profiler SPConfigurationProfileDataType | grep -c "blankcd"`
	if [ ${profiles_blankcd} -gt 1 ] ; then
		printf "	%b	Einstellungen für leere CDs werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für leere CDs werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für leere CDs (erlauben und mit Authentisierung)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then		
		local blankcd_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/blankcd/,/);/p' | grep -c "deny"`
		if [ ${blankcd_deny} == 1 ] ; then
			printf "	%b	leere CDs dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
			
		else
		
			local blankcd_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/blankcd/,/);/p' | grep -c "authenticate"`
			if [ ${blankcd_authenticate} == 1 ] ; then
				printf "	%b	leere CDs dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	leere CDs dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
	fi
	printf "\n" | tee -a ${Audit_file}
	
	#################################################
	# 
	# leere DVD
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für leer DVDs vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_blankdvd=`system_profiler SPConfigurationProfileDataType | grep -c "blankdvd"`
	if [ ${profiles_blankdvd} -gt 1 ] ; then
		printf "	%b	Einstellungen für leere DVDs werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		printf "	%b	Einstellungen für leere DVDs werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}		
	fi
		
	printf "	%b	Überprüfe die Einstellungen für leere DVDs (erlauben und mit Authentisierung)  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then	
		local blankdvd_deny=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/blankdvd/,/);/p' | grep -c "deny"`
		if [ ${blankdvd_deny} == 1 ] ; then
			printf "	%b	leere DVDs dürfen nicht verwendet werden %s\\n"  | tee -a ${Audit_file}
			
		else
		
			local blankdvd_authenticate=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/blankdvd/,/);/p' | grep -c "authenticate"`
			if [ ${blankdvd_authenticate} == 1 ] ; then
				printf "	%b	leere DVDs dürfen nur mit Authentisierung verwendet werden %s\\n" "${TICK}" | tee -a ${Audit_file}
			else
				printf "	%b	leere DVDs dürfen ohne Authentisierung verwendet werden %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
	fi
	printf "\n" | tee -a ${Audit_file}

	#################################################
	# 
	# Bei Systemabmeldung alle Medien auswerfen
	#
	###################################################
	printf "	%b	Überprüfe, wie viele Profile Einstellungen für Wechselmedien auswerfen bei Abmeldung vorgeben.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	local profiles_logout_eject=`system_profiler SPConfigurationProfileDataType | grep -c "logout-eject"`
	if [ ${profiles_logout_eject} -gt 1 ] && [ ${profiles_logout_eject} != 0 ]; then
		printf "	%b	Einstellungen für Wechselmedien auswerfen bei Abmeldung werden von mehr als einem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	elif [ ${profiles_logout_eject} == 1 ]; then
		
		printf "	%b	Einstellungen für für Wechselmedien auswerfen bei Abmeldung werden von einem Profile vorgegeben. %s\\n" "${TICK}" | tee -a ${Audit_file}
	
	elif [ ${profiles_logout_eject} == 0 ]; then
		printf "	%b	Einstellungen für für Wechselmedien auswerfen bei Abmeldung werden von keinem Profile vorgegeben. %s\\n" "${CROSS}" | tee -a ${Audit_file}
		
	fi
		
	if [ ${profiles_logout_eject} -gt 1 ] && [ ${profiles_logout_eject} != 0 ]; then
		printf "	%b	Überprüfe die Einstellungen für Wechselmedien auswerfen bei Abmeldung  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ -e /Library/Managed\ Preferences/com.apple.systemuiserver.plist ] ; then	
			local medium_logout_eject=`defaults read  /Library/Managed\ Preferences/com.apple.systemuiserver.plist | sed -n '/logout-eject/,/);/p' | grep -c "all-media"`
			if [ ${medium_logout_eject} == 1 ] ; then
				printf "	%b	Wechselmedien werden vor dem Abmelden vom System ausgeworfen. %s\\n" "${TICK}"  | tee -a ${Audit_file}
						
			else
				printf "	%b	Wechselmedien werden vor dem Abmelden vom System nicht ausgeworfen %s\\n" "${CROSS}" | tee -a ${Audit_file}
			fi
		fi
	fi
	
else
	printf "	%b	Es ist kein Profilemanager hinterlegt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	printf "	%b	Es werden zentral keine Einstellungen für die interne Festplatte vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für die externe Festplatte vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für Disk-Images vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für DVD-RAMs vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für CDs und CD-ROMs vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für DVDs vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für leer CDs vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für leer DVDs vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	printf "	%b	Es werden zentral keine Einstellungen für Wechselmedien auswerfen bei Abmeldung vorgeben.  %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	#################################################
	# 
	# Kernelmodul
	#
	###################################################
	printf "	%b	Überprüfe, ob das Kernebundel (KEXT) für USB-Wechselmedien installiert ist %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	ls /System/Library/Extensions/ >> ${evidence_folder}/SYS21M24_all_active_KEXT_files
	if [ -e /System/Library/Extensions/IOUSBMassStorageClass.kext ]; then
		printf "	%b	Das Kernebundel IOUSBMassStorageClass.kext für USB-Wechselmedien ist installiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
	else
		printf "	%b	Das Kernebundel IOUSBMassStorageClass.kext für USB-Wechselmedien ist nicht installiert %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Das Entfernen von Kernelmodulen wird von der Firma Apple nicht empfohlen. Einstellungen sollten durch einen Profilemanager erfolgen. %s\\n" | tee -a ${Audit_file}
		printf "	%b	Achtung bei größeren Systemupdates oder macOS-Upgrades wird das Kernelmodul wieder installiert %s\\n" | tee -a ${Audit_file}		
	fi	
fi
printf "\n" | tee -a ${Audit_file}

}

SYS21M24
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A25 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A25 Richtlinie zur sicheren IT-Nutzung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE eine Richtlinie erstellt werden, in der für alle Mitarbeiter transparent beschrieben wird,
	welche Rahmenbedingungen bei der IT-Nutzung eingehalten werden müssen und welche Sicherheitsmaßnahmen 
	zu ergreifen sind. Die Richtlinie SOLLTE folgende Punkte abdecken:
	- Sicherheitsziele der Institution
	- Wichtige Begriffe
	- Aufgaben und Rollen mit Bezug zur Informationssicherheit
	- Ansprechpartner zu Fragen der Informationssicherheit
	- Von den Mitarbeitern umzusetzende und einzuhaltende Sicherheitsmaßnahmen
	Die Richtlinie SOLLTE allen Benutzern zur Kenntnis gegeben werden. Jeder neue Benutzer SOLLTE die 
	Kenntnisnahme der Richtlinie bestätigen, bevor er die Informationstechnik nutzen darf. Nach größeren 
	Änderungen an der Richtlinie oder nach spätestens zwei Jahren SOLLTE eine erneute Bestätigung erforderlich." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M25 ()

{
	printf "	%b	Bitte beim Sicherheitsmanagement erfragen, in welchem Dokument diese geregelt wird und für 
		diese Überprüfung angeben. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M25
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A26 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A26 Schutz von Anwendungen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Um die Ausnutzung von Schwachstellen in Anwendungen zu erschweren, SOLLTE ASLR und DEP/NX im Kernel aktiviert 
	und von den Anwendungen genutzt werden. Sicherheitsfunktionen des Kernels und der Standardbibliotheken wie z. B. 
	Heap- und Stackschutz SOLLTEN NICHT deaktiviert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}
###################################################
# 
# SYS.2.1.M26 SIP Status
#
###################################################

SYS21M26_SIP ()
{
printf "	%b	Überprüfung des System Integrity Protection (SIP) Status %s\\n" "${INFO}" | tee -a ${Audit_file}
SIPSTATUS=`csrutil status 2> /dev/null |  awk ' { print $5 }'`

csrutil status 2> /dev/null >> ${evidence_folder}/SYS21M26_System_Integrity_Status

if [ ${SIPSTATUS} == "enabled." ]; then
	printf "	%b	System Integrity Protection (SIP) ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	System Integrity Protection (SIP) ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi

printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M26 Xprotect Status
#
###################################################

SYS21M26_Xprotect ()
{
printf "	%b	Überprüfung des Xprotect Status %s\\n" "${INFO}" | tee -a ${Audit_file}

defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist 2> /dev/null >> ${evidence_folder}/SYS21M26_XProtect

if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -gt 9 ]]; then

  last_xprotect_update_epoch_time=$(printf "%s\n" `for i in $(pkgutil --pkgs=".*XProtect.*"); do pkgutil --pkg-info $i | awk '/install-time/ {print $2}'; done` | sort -n | tail -1)
  last_xprotect_update_human_readable_time=`/bin/date -r "$last_xprotect_update_epoch_time" '+%d.%m.%Y %H:%M:%S'`
  XPROTECTCHECKRESULT="$last_xprotect_update_human_readable_time"
  printf " 		Die letzte Xprotect Änderung erfolgte am "${XPROTECTCHECKRESULT}"\\n" | tee -a ${Audit_file}
  
fi

printf "\n\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M26 Gatekeeper Status
#
###################################################

SYS21M26_Gatekeeper ()
{
printf "	%b	Überprüfung des Gatekeeper Status %s\\n" "${INFO}" | tee -a ${Audit_file}

GATEKEEPERSTATUS=`spctl --status 2> /dev/null |  awk ' { print $2 }'`
spctl --status 2> /dev/null >> ${evidence_folder}/SYS21M26_Gatekeeper

if [ ${GATEKEEPERSTATUS} == "enabled" ]; then
	printf "	%b	Gatekeeper ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Gatekeeper ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
}

SYS21M26_SIP
sleep 0.5

SYS21M26_Xprotect
sleep 0.5

SYS21M26_Gatekeeper
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A27 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A27 Geregelte Außerbetriebnahme eines Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bei der Außerbetriebnahme eines Clients SOLLTE sichergestellt werden, dass keine wichtigen Daten, die eventuell 
	auf den verbauten Datenträgern gespeichert sind, verloren gehen und dass keine sensitiven Daten zurückbleiben. 
	Es SOLLTE einen Überblick darüber geben, welche Daten wo auf den IT-Systemen gespeichert sind. Es SOLLTE eine 
	Checkliste erstellt werden, die bei der Außerbetriebnahme eines IT-Systems abgearbeitet werden kann. Diese 
	Checkliste SOLLTE mindestens Aspekte zur Datensicherung weiterhin benötigter Daten und dem anschließenden 
	sicheren Löschen aller Daten umfassen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M27 ()

{
	printf "	%b	Bitte das Betriebsführungskonzept sowie Betriebshanbücher für dieses
		System angeben. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
	
	printf "	%b	Folgen Sie den Hinweisen aus Artikel HT204063 von Apple  %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "	%b	Der Link lautet https://support.apple.com/de-de/HT204063 %s\\n" | tee -a ${Audit_file}
}

SYS21M27
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


###################################################
#
# SYS.2.4.A4 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A4 Verwendung der Festplattenverschlüsselung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Festplatten SOLLTEN insbesondere bei mobilen Macs (z.B. MacBooks) verschlüsselt werden. Wird dazu 
	die in macOS integrierte Funktion FileVault verwendet, so DARF das Schlüsselmaterial NICHT online
	bei Apple gespeichert werden. Der von FileVault erzeugte Wiederherstellungsschlüssel MUSS an einem
	sicheren Ort aufbewahrt werden." | tee -a ${Audit_file}

	printf "\n\n" | tee -a ${Audit_file}
	
SYS24M4 ()
{
printf "	%b	Überprüfe, ob die Festplattenverschlüsselung FileVault aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}

FILEVAULTSTATUS=`fdesetup status -extended | grep "FileVault is" | awk ' { print $3 }'`
fdesetup status -extended >> ${evidence_folder}/SYS24M4_File_Vault_Status

if [ ${FILEVAULTSTATUS} == "Off." ]; then
	printf "	%b	Die Festplattenverschlüsselung FileVault ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Die Festplattenverschlüsselung FileVault ist aktiv. %s\\n" "${TICK}" | tee -a ${Audit_file}
			
			FILEVAULTVOLUME=`fdesetup status -extended | grep "Volume" | awk ' { print $3 }'`
			
			printf %s "		Es wird als Festplattenvolume genutzt: "${FILEVAULTVOLUME}"" | tee -a ${Audit_file}
			printf "\n" | tee -a ${Audit_file}
			
			sudo fdesetup list >> ${evidence_folder}/SYS24M4_FILEFAULTUSERS_List
			printf "	%b	Zeige die Kurznamen und UUIDs der freigegebenen FileVault-Benutzer. %s\\n" "${INFO}" | tee -a ${Audit_file}
			while read FILEFAULTUSERS
			do
				printf " 		\""${FILEFAULTUSERS}"\" \\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS24M4_FILEFAULTUSERS_List
						
			printf "\n" | tee -a ${Audit_file}
		fi
		printf "\n" | tee -a ${Audit_file}
}


SYS24M4
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.A5 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A5 Erhöhung des Schutzes von Daten %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die in macOS integrierten Ortungsdienste SOLLTEN deaktiviert werden. Heruntergeladene Daten SOLLTEN
	nicht automatisch geöffnet werden. Inhalte von optischen und anderen Medien SOLLTEN nicht automatisch
	ausgeführt werden." | tee -a ${Audit_file}

	printf "\n\n" | tee -a ${Audit_file}
	
###################################################
# 
# SYS.2.4.M5 Ortungsdienste
#
###################################################
sub_SYS24M5_Ortungsdienste ()
{
#domains | tr ',' '\n'
printf "	%b	Überprüfe die aktuellen Einstellungen für die Verwendung von Ortungsdiensten. %s\\n" "${INFO}" | tee -a ${Audit_file}

if [ $(sudo defaults read /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.${HW_UUID}.plist | grep -c "LocationServicesEnabled") != "0" ]; then
	LOCATIONSERVICE=`sudo defaults read /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.${HW_UUID}.plist | grep "LocationServicesEnabled" | awk ' { print $3 }'`
	sudo defaults read /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.${HW_UUID}.plist >> ${evidence_folder}/SYS24M5_Location_Service
	if [ ${LOCATIONSERVICE} == "0;" ]; then
	printf "	%b	Der Ortungsdienst ist global für Hardware UUID ${HW_UUID} deaktiviert %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
						printf "	%b	Der Ortungsdienst ist global für Hardware UUID ${HW_UUID} aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		fi
	else
			printf "	%b	Der Ortungsdienst ist global für Hardware UUID ${HW_UUID} aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
}

SYS24M5_Ortungsdienste ()
{
if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -ge 10 ]] && [[ ${OS_vers_minor} -lt 14 ]]; then

	sub_SYS24M5_Ortungsdienste

else
	printf "	%b 	Überprüfe die macOS Version und ob der Pfad /var durch Systemintegritätsschutz (SIP) geschützt wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
		
	SIPSTATUS=`csrutil status 2> /dev/null |  awk ' { print $5 }'`
	if [ ${SIPSTATUS} == "enabled." ]; then
		printf "	%b	System Integrity Protection (SIP) ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		# ab macOs 10.14 wird mittels SIP der Zugriff auf die Pfade /System , /usr , /bin , /sbin und /var geschützt
		printf "	%b	Die Zugriffe auf die Pfade /System , /usr , /bin , /sbin und /var sind durch SIP unter macOS ${OSXVERSION} Build-Nummer ${OS_vers_build} geschützt. %s\\n" "${TICK}"
		printf "	%b	Es kann nicht überprüft werden, ob der Ortungsdienst global für Hardware UUID ${HW_UUID} aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
	else
		printf "	%b	System Integrity Protection (SIP) ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Die Zugriffe auf den Pfad /System , /usr , /bin , /sbin und /var sind durch SIP nicht geschützt. %s\\n" "${CROSS}"

		sub_SYS24M5_Ortungsdienste
	
	fi
fi
	
printf "\n" | tee -a ${Audit_file}
}

###################################################
#
# SYS.2.4.M5 Safari Dateien nicht auto öffnen
#
###################################################

SYS24M5_Safari_AUTO_FILE ()
{
printf "	%b	Überprüfe, ob Safari sichere Dateiendungen automatisch öffnet. %s\\n" "${INFO}" | tee -a ${Audit_file}
defaults read com.apple.Safari 2> /dev/null >> ${evidence_folder}/SYS24M5_Browser_Safari
if [ $(defaults read com.apple.Safari 2> /dev/null | grep "AutoOpenSafeDownloads" | wc -l) == "0" ]; then
	
		printf "	%b	Die Einstellung in Safari für das automatisch Öffnen von Dateien mit sicheren Endungen
		ist nicht gesetzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
		printf "	%b	Safari öffnet somit automatisch Dateien mit sicheren Endungen %s\\n" "${CROSS}" | tee -a ${Audit_file}
	
	else
		if [ $(defaults read com.apple.Safari | grep "AutoOpenSafeDownloads" | awk ' { print $3 }') != "0;" ]; then
				printf "	%b	Safari öffnet automatisch Dateien mit sicheren Endungen %s\\n" "${CROSS}" | tee -a ${Audit_file}
			else
				printf "	%b	Safari öffnet nicht automatisch Dateien mit sicheren Endungen %s\\n" "${TICK}" | tee -a ${Audit_file}
		fi
			
fi

printf "\n" | tee -a ${Audit_file}

}


###################################################
# 
# SYS.2.4.M5 CD nicht auto öffnen
#
###################################################

SYS24M5_CD_AUTO ()
{
	# possible values for setting_value are:
    # action 1 = "Ignore"
    # action 2 = "Ask what to do"
    # action 5 = "Open other application"
    # action 6 = "Run script"
    # action 100 = "Open Finder"
    # action 101 = "Open iTunes"
    # action 102 = "Open Disk Utility"
    # action 105 = "Open DVD Player"
    # action 106 = "Open iDVD"
    # action 107 = "Open Photos"
    # action 109 = "Open Front Row"
	
while read User_gt_500
do
	printf "	%b	Überprüfe für den  Benutzer ${User_gt_500}, ob Autoplay für leere CDs aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
    local friendly_name="Für den Benutzer ${User_gt_500} ist folgende Aktion für eine leere CD eingestellt"

    if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist ]; then
		defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist >> ${evidence_folder}/SYS24M5_CD_DVD_Autoplay_${User_gt_500}
       local  dict_exists=` defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | grep -c "com.apple.digihub.blank.cd.appeared"`
		local setting_value=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | sed -n '/com.apple.digihub.blank.cd.appeared/,/;/p' | grep "action" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
    	if [ $dict_exists == 1 ]; then
       	 if [ $setting_value == 1 ]; then
				printf "	%b	$friendly_name \"Ignore\" %s\\n" "${TICK}" | tee -a ${Audit_file} ;
    		elif [ $setting_value == "5" ]; then
				printf "	%b	$friendly_name \"Open other application\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "6" ]; then
				printf "	%b	$friendly_name \"Run script\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "100" ]; then
				printf "	%b	$friendly_name \"Open Finder\" %s\\n" "${CROSS}"| tee -a ${Audit_file};
    		elif [ $setting_value == "101" ]; then
				printf "	%b	$friendly_name \"Open iTunes\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
			 elif [ $setting_value == "102" ]; then
				printf "	%b	$friendly_name \"Open Disk Utility\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "105" ]; then
				printf "	%b	$friendly_name \"Open DVD Player\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "106" ]; then
				printf "	%b	$friendly_name \"Open iDVD\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "107" ]; then
				printf "	%b	$friendly_name \"Open Photos\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "109" ]; then
				printf "	%b	$friendly_name \"Open Front Row\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
   			else
				 # if the key doesn't exist or is 2, the setting is "Ask what to do"
				printf "	%b	$friendly_name \"Ask what to do\" %s\\n" "${TICK}" | tee -a ${Audit_file};
       	 fi

        else
        printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
        fi
	else
		printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
    fi

done < ${Audit_folder}/TMP_User_List_gt_500
printf "\n" | tee -a ${Audit_file}

}


###################################################
# 
# SYS.2.4.M5 DVD nicht auto öffnen
#
###################################################

SYS24M5_DVD_AUTO ()
{
	
while read User_gt_500
do
	printf "	%b	Überprüfe für den  Benutzer ${User_gt_500}, ob Autoplay für leere DVDs aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
    local friendly_name="Für den Benutzer ${User_gt_500} ist folgende Aktion für eine leere DVD eingestellt"

    if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist ]; then
		defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist >> ${evidence_folder}/SYS24M5_CD_DVD_Autoplay_${User_gt_500}
       local  dict_exists=` defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | grep -c "com.apple.digihub.blank.dvd.appeared"`
		local setting_value=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | sed -n '/com.apple.digihub.blank.dvd.appeared/,/;/p' | grep "action" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
    	if [ $dict_exists == 1 ]; then
       	 if [ $setting_value == 1 ]; then
				printf "	%b	$friendly_name \"Ignore\" %s\\n" "${TICK}" | tee -a ${Audit_file} ;
    		elif [ $setting_value == "5" ]; then
				printf "	%b	$friendly_name \"Open other application\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "6" ]; then
				printf "	%b	$friendly_name \"Run script\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "100" ]; then
				printf "	%b	$friendly_name \"Open Finder\" %s\\n" "${CROSS}"| tee -a ${Audit_file};
    		elif [ $setting_value == "101" ]; then
				printf "	%b	$friendly_name \"Open iTunes\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
			 elif [ $setting_value == "102" ]; then
				printf "	%b	$friendly_name \"Open Disk Utility\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "105" ]; then
				printf "	%b	$friendly_name \"Open DVD Player\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "106" ]; then
				printf "	%b	$friendly_name \"Open iDVD\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "107" ]; then
				printf "	%b	$friendly_name \"Open Photos\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "109" ]; then
				printf "	%b	$friendly_name \"Open Front Row\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
   			else
				 # if the key doesn't exist or is 2, the setting is "Ask what to do"
				printf "	%b	$friendly_name \"Ask what to do\" %s\\n" "${TICK}" | tee -a ${Audit_file};
       	 fi

        else
        printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
        fi
	else
		printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
    fi

done < ${Audit_folder}/TMP_User_List_gt_500
printf "\n" | tee -a ${Audit_file}
}

		
###################################################
# 
# SYS.2.4.M5 Music CD nicht auto öffnen
#
###################################################

SYS24M5_MCD_AUTO ()
{

while read User_gt_500
do
	printf "	%b	Überprüfe für den  Benutzer ${User_gt_500}, ob Autoplay für Music-CDs aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
    local friendly_name="Für den Benutzer ${User_gt_500} ist folgende Aktion für eine Music-CD eingestellt"

    if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist ]; then
		defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist >> ${evidence_folder}/SYS24M5_CD_DVD_Autoplay_${User_gt_500}
       local  dict_exists=` defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | grep -c "com.apple.digihub.cd.music.appeared"`
		local setting_value=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | sed -n '/com.apple.digihub.cd.music.appeared/,/;/p' | grep "action" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
    	if [ $dict_exists == 1 ]; then
       	 if [ $setting_value == 1 ]; then
				printf "	%b	$friendly_name \"Ignore\" %s\\n" "${TICK}" | tee -a ${Audit_file} ;
    		elif [ $setting_value == "5" ]; then
				printf "	%b	$friendly_name \"Open other application\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "6" ]; then
				printf "	%b	$friendly_name \"Run script\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "100" ]; then
				printf "	%b	$friendly_name \"Open Finder\" %s\\n" "${CROSS}"| tee -a ${Audit_file};
    		elif [ $setting_value == "101" ]; then
				printf "	%b	$friendly_name \"Open iTunes\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
			 elif [ $setting_value == "102" ]; then
				printf "	%b	$friendly_name \"Open Disk Utility\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "105" ]; then
				printf "	%b	$friendly_name \"Open DVD Player\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "106" ]; then
				printf "	%b	$friendly_name \"Open iDVD\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "107" ]; then
				printf "	%b	$friendly_name \"Open Photos\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "109" ]; then
				printf "	%b	$friendly_name \"Open Front Row\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
   			else
				 # if the key doesn't exist or is 2, the setting is "Ask what to do"
				printf "	%b	$friendly_name \"Ask what to do\" %s\\n" "${TICK}" | tee -a ${Audit_file};
       	 fi

        else
        printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
        fi
	else
		printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
    fi

done < ${Audit_folder}/TMP_User_List_gt_500
printf "\n" | tee -a ${Audit_file}	
	

}


###################################################
# 
# SYS.2.4.M5 Bild CD nicht auto öffnen
#
###################################################

SYS24M5_PCD_AUTO ()
{
	
while read User_gt_500
do
	printf "	%b	Überprüfe für den  Benutzer ${User_gt_500}, ob Autoplay für Bild-CDs aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
    local friendly_name="Für den Benutzer ${User_gt_500} ist folgende Aktion für eine Bild-CD eingestellt"

    if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist ]; then
		defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist >> ${evidence_folder}/SYS24M5_CD_DVD_Autoplay_${User_gt_500}
       local  dict_exists=` defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | grep -c "com.apple.digihub.cd.picture.appeared"`
		local setting_value=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | sed -n '/com.apple.digihub.cd.picture.appeared/,/;/p' | grep "action" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
    	if [ $dict_exists == 1 ]; then
       	 if [ $setting_value == 1 ]; then
				printf "	%b	$friendly_name \"Ignore\" %s\\n" "${TICK}" | tee -a ${Audit_file} ;
    		elif [ $setting_value == "5" ]; then
				printf "	%b	$friendly_name \"Open other application\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "6" ]; then
				printf "	%b	$friendly_name \"Run script\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "100" ]; then
				printf "	%b	$friendly_name \"Open Finder\" %s\\n" "${CROSS}"| tee -a ${Audit_file};
    		elif [ $setting_value == "101" ]; then
				printf "	%b	$friendly_name \"Open iTunes\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
			 elif [ $setting_value == "102" ]; then
				printf "	%b	$friendly_name \"Open Disk Utility\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "105" ]; then
				printf "	%b	$friendly_name \"Open DVD Player\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "106" ]; then
				printf "	%b	$friendly_name \"Open iDVD\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "107" ]; then
				printf "	%b	$friendly_name \"Open Photos\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "109" ]; then
				printf "	%b	$friendly_name \"Open Front Row\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
   			else
				 # if the key doesn't exist or is 2, the setting is "Ask what to do"
				printf "	%b	$friendly_name \"Ask what to do\" %s\\n" "${TICK}" | tee -a ${Audit_file};
       	 fi

        else
        printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
        fi
	else
		printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
    fi

done < ${Audit_folder}/TMP_User_List_gt_500
printf "\n" | tee -a ${Audit_file}		

}


###################################################
# 
# SYS.2.4.M5 Video DVD nicht auto öffnen
#
###################################################

SYS24M5_VDVD_AUTO ()
{
	
while read User_gt_500
do
	printf "	%b	Überprüfe für den  Benutzer ${User_gt_500}, ob Autoplay für Video-DVDs aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
    local friendly_name="Für den Benutzer ${User_gt_500} ist folgende Aktion für eine Video-DVD eingestellt"

    if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist ]; then
		defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist >> ${evidence_folder}/SYS24M5_CD_DVD_Autoplay_${User_gt_500}
       local  dict_exists=` defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | grep -c "com.apple.digihub.dvd.video.appeared"`
		local setting_value=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.digihub.plist | sed -n '/com.apple.digihub.dvd.video.appeared/,/;/p' | grep "action" | egrep -o " [0-9]+;$" | egrep -o "[0-9]+"`
    	if [ $dict_exists == 1 ]; then
       	 if [ $setting_value == 1 ]; then
				printf "	%b	$friendly_name \"Ignore\" %s\\n" "${TICK}" | tee -a ${Audit_file} ;
    		elif [ $setting_value == "5" ]; then
				printf "	%b	$friendly_name \"Open other application\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "6" ]; then
				printf "	%b	$friendly_name \"Run script\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "100" ]; then
				printf "	%b	$friendly_name \"Open Finder\" %s\\n" "${CROSS}"| tee -a ${Audit_file};
    		elif [ $setting_value == "101" ]; then
				printf "	%b	$friendly_name \"Open iTunes\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
			 elif [ $setting_value == "102" ]; then
				printf "	%b	$friendly_name \"Open Disk Utility\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "105" ]; then
				printf "	%b	$friendly_name \"Open DVD Player\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "106" ]; then
				printf "	%b	$friendly_name \"Open iDVD\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "107" ]; then
				printf "	%b	$friendly_name \"Open Photos\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
    		elif [ $setting_value == "109" ]; then
				printf "	%b	$friendly_name \"Open Front Row\" %s\\n" "${CROSS}" | tee -a ${Audit_file};
   			else
				 # if the key doesn't exist or is 2, the setting is "Ask what to do"
				printf "	%b	$friendly_name \"Ask what to do\" %s\\n" "${TICK}" | tee -a ${Audit_file};
       	 fi

        else
        printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
        fi
	else
		printf "	%b	keine Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${CROSS}" | tee -a ${Audit_file};
    fi
done < ${Audit_folder}/TMP_User_List_gt_500
printf "\n" | tee -a ${Audit_file}		

}

SYS24M5_Ortungsdienste 
sleep 0.5

SYS24M5_Safari_AUTO_FILE
sleep 0.5

SYS24M5_CD_AUTO
sleep 0.5

SYS24M5_DVD_AUTO
sleep 0.5

SYS24M5_MCD_AUTO
sleep 0.5

SYS24M5_PCD_AUTO
sleep 0.5

SYS24M5_VDVD_AUTO
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.A6 BSI
#
###################################################

printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A6 Verwendung aktueller Hardware %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bei der Beschaffung von neuen Macs SOLLTE auf aktuelle Modelle zurückgegriffen werden. Werden 
	vorhandene Macs eingesetzt, SOLLTE überprüft werden, ob diese weiterhin von Apple mit 
	Sicherheits-Updates versorgt werden. Werden die Macs nicht mehr durch Apple unterstützt, so 
	SOLLTEN sie nicht mehr verwendet werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}

SYS24M6 ()
{
printf "	%b	Überprüfe, welche Hardware eingesetzt wird. %s\\n" "${INFO}" | tee -a ${Audit_file}
printf " 		Model Name: "${MODELNAME}" \\n" | tee -a ${Audit_file}
printf "		Model Identifier: "${MODELIDENTIFIER}" \\n" | tee -a ${Audit_file}
printf "		Boot ROM Version: "${BOOTROM}" \\n" | tee -a ${Audit_file}
printf "		macOS Version: "${OSXVERSION}" \\n" | tee -a ${Audit_file}
printf "	%b	Zum bestimmen des richtigen Models an Hand des Model Identifier bitte die App >MacTrack< verwenden %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Aufruf des Links https://support.apple.com/de-de/HT201624 %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	Folgende Vintage Informationen wurden gefunden für den Model Name \""${MODELNAME}"\": %s\\n" "${ATTENTION}" | tee -a ${Audit_file}

if [ ${MODELNAME} != "Apple" ]; then
	
VINTAGE=`curl --silent https://support.apple.com/de-de/HT201624 --stderr - | grep ${MODELNAME} | sed 's/<li>//' | sed 's/<\/li>/ <--> /'`
			printf %s "\
		"${VINTAGE}"" | tee -a ${Audit_file}
			printf "\n\n" | tee -a ${Audit_file}
			
else
		printf "	%b		Für das System ${MODELIDENTIFIER} liefert Apple keine Vintage Informationen. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
fi
}

SYS24M6
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.A7 BSI
#
###################################################

printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A7 Zwei-Faktor-Authentisierung für Apple-ID [Benutzer] %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die Zwei-Faktor-Authentisierung für die Verwendung des Apple-ID-Kontos SOLLTE aktiviert werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}

SYS24M7 ()
{
	printf "	%b	Dies ist eine Einstellung der Apple-ID. Bitte überprüfen Sie Ihr Apple-Konto. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
}

SYS24M7
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
	
###################################################
# 
# SYS.2.4.A8 BSI
#
###################################################

printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A8 Keine Nutzung von iCloud für sensible Daten [Benutzer] %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE verhindert werden, dass Daten zwischen mehreren Geräten über iCloud-Dienste wie
	Hand‑off synchronisiert werden. Stattdessen SOLLTEN Daten nur über selbst betriebene Dienste
	synchronisiert werden. Sensible Daten SOLLTEN NICHT in iCloud gespeichert werden. Entwürfe
	(E-Mails, Dokumente etc.) SOLLTEN NICHT automatisch in iCloud gespeichert werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}


###################################################
# 
# SYS.2.4.M8 AirDrop
#
###################################################

SYS24M8_AirDrop ()
{

while read User_gt_500
do
printf "	%b	Überprüfe, ob AirDrop für das Benutzerkonto ${User_gt_500} aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ -e /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist ]; then
	
	defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist >> ${evidence_folder}/SYS24M8_AirDrop
	local dict_exists=`defaults read /Users/${User_gt_500}/Library/Preferences/com.apple.NetworkBrowser.plist 2> /dev/null| grep -c "DisableAirDrop"`
	if [ $dict_exists == 1 ]; then
		printf "	%b	Für das Benutzerkonto ${User_gt_500} wird der Test durchgeführt  %s\\n" | tee -a ${Audit_file}
			printf "	%b	Für den Benutzer ${User_gt_500} ist AirDrop aktiv %s\\n" "${CROSS}"	| tee -a ${Audit_file}
			
   		else
			printf "	%b	Für den Benutzer ${User_gt_500} ist die Einstellung für AirDrop nicht gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
        fi
	else
	printf "	%b	Die Einstellung für AirDrop ist für den Benutzer ${User_gt_500} global nicht vorhanden und somit ist AirDrop nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
fi 
printf "\n" | tee -a ${Audit_file}
done < ${Audit_folder}/TMP_User_List_gt_500

}

###################################################
# 
# SYS.2.4.M8 iCloud
#
###################################################

SYS24M8_iCloud ()
{

while read User_gt_500
do
printf "	%b	Überprüfe, ob iCloud global für den Benutzer ${User_gt_500} aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}	
if [ -e /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist ]; then
	defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist 2> /dev/null >> ${evidence_folder}/SYS24M8_iCloud
	local dict_exists=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist 2> /dev/null | sed -n '/Accounts/,/(/p' | grep "AccountID" | awk ' { print $3 }' | sed 's/;//' | wc -l`
	if [ ${dict_exists} == 1 ]; then
		printf "	%b	Für den Benutzer ${User_gt_500} ist iCloud konfiguriert %s\\n" "${CROSS}" | tee -a ${Audit_file}
		local iCloud_Account_Description=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountDescription" | awk ' { print $3 }' | sed 's/;//'` 
		local iCloud_Account_ID=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountID" | awk ' { print $3 }' | sed 's/;//'`
		local iCloud_Display_Name=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "DisplayName" | awk ' { print $3 " "$4 }' | sed 's/;//'`
		local iCloud_Account_UUID=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "AccountUUID" | awk ' { print $3 }' | sed 's/;//'`
		local iCloud_Logged_In=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | sed -n '/Accounts/,/(/p' | grep "LoggedIn" | awk ' { print $3 }' | sed 's/;//'`
		
		printf "	%b	Folgende Benutzerwerte sind hinterlegt %s\\n" "${INFO}" | tee -a ${Audit_file}
		printf "	%b		Display Name: $iCloud_Display_Name %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account Description: $iCloud_Account_Description %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account ID: $iCloud_Account_ID %s\\n" | tee -a ${Audit_file}
		printf "	%b		Account UUID: $iCloud_Account_UUID %s\\n" | tee -a ${Audit_file}
		
		if [ ${dict_exists} == 1 ]; then
			printf "	%b		Login: aktiv %s\\n" | tee -a ${Audit_file}
		else 
			printf "	%b		Login: inaktiv %s\\n" | tee -a ${Audit_file}
		fi

	printf "\n" | tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - Contacts
	#
	###################################################

		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Contacts") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist 2> /dev/null | grep -B2 -A6 "CONTACTS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_Contacts=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  2> /dev/null | grep -B2 -A6 "CONTACTS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe Für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Kontakte  %s\\n" "${INFO}" | tee -a ${Audit_file}

			if [ ${iCoud_Enable_Exits} == 1 ]; then				
				if [ ${iCoud_Contacts} == 1 ]; then
					printf "	%b	Für den Benutzer ${User_gt_500} werden Kontakte in die iCloud synchronisiert %s\\n" "${INFO}" | tee -a ${Audit_file}
				else
					printf "	%b	Für den Benutzer ${User_gt_500} werden Kontakte nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Für den Benutzer ${User_gt_500} werden Kontakte nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Für den Benutzer ${User_gt_500} wurden keine iCloud-Einstellungen für Kontakte gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi

	printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - mobile Documents
	#
	###################################################

		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Ubiquity") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "MOBILE_DOCUMENTS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_MOBILE_DOCUMENTS=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "MOBILE_DOCUMENTS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Dokumente  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then					
				if [ ${iCoud_MOBILE_DOCUMENTS} == 1 ]; then
					printf "	%b	Documente werden in die iCloud für den Benutzer ${User_gt_500} synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Dokumente werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Dokumente werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Dokumente für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
	printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - PHOTO STREAM
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Photos") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A3 "PHOTO_STREAM" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_PHOTO_STREAM=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A3 "PHOTO_STREAM" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Fotostream  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_PHOTO_STREAM} == 1 ]; then
					printf "	%b	Fotos werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Fotos werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Fotos werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Fotos für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
	printf "\n"	| tee -a ${Audit_file}
	

	###################################################
	# 
	# SYS.2.4.M8 iCloud - CALENDAR
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Calendars") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "CALENDAR" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_CALENDAR=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "CALENDAR" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Kalender  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_CALENDAR} == 1 ]; then
					printf "	%b	Kalender werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Kalender werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Kalender werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Kalender für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
	printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - REMINDERS
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Reminders") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "REMINDERS" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_REMINDERS=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A6 "REMINDERS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Erinnerungen  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_REMINDERS} == 1 ]; then
					printf "	%b	Erinnerungen werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Erinnerungen werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Erinnerungen werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Erinnerungen für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - BOOKMARKS
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Bookmarks") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A7 "BOOKMARKS" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_BOOKMARKS=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B2 -A7 "BOOKMARKS" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Bookmarks  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_BOOKMARKS} == 1 ]; then
					printf "	%b	Bookmarks werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Bookmarks werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Bookmarks werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Bookmarks für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}	
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - NOTES
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Notes") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B5 -A14 "com.apple.Dataclass.Notes" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_NOTES=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B5 -A14 "com.apple.Dataclass.Notes" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Notizen  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_NOTES} == 1 ]; then
					printf "	%b	Notizen werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Notizen werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Notizen werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Notizen für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	

	###################################################
	# 
	# SYS.2.4.M8 iCloud - MAIL_AND_NOTES
	# 
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Mail") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B5 -A14 "com.apple.Dataclass.Mail" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_MAIL_AND_NOTES=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B5 -A14 "com.apple.Dataclass.Mail" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für E-Mails  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_MAIL_AND_NOTES} == 1 ]; then
					printf "	%b	E-Mails werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	E-Mails werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	E-Mails werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für E-Mail für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - SIRI
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.Siri") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A1 "com.apple.Dataclass.Siri" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_SIRI=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A1 "com.apple.Dataclass.Siri" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe, ob Siri für den Benutzer ${User_gt_500} benutzt wird %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_SIRI} == 1 ]; then
					printf "	%b	Siri wird für den Benutzer ${User_gt_500} benutzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Siri wird für den Benutzer ${User_gt_500} nicht benutzt %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Siri wird für den Benutzer ${User_gt_500} nicht benutzt %s\\n" "${TICK}" | tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Siri für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - KEYCHAIN_SYNC
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.KeychainSync") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A3 "com.apple.Dataclass.KeychainSync" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_KEYCHAIN_SYNC=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A3 "com.apple.Dataclass.KeychainSync" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für den Schlüsselbund  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_KEYCHAIN_SYNC} == 1 ]; then
					printf "	%b	Die Passwörter aus dem Schlüsselbund werden für den Benutzer ${User_gt_500} in die iCloud synchronisiert %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Die Passwörter aus dem Schlüsselbund werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Die Passwörter aus dem Schlüsselbund werden für den Benutzer ${User_gt_500} nicht in die iCloud synchronisiert %s\\n" "${TICK}"	| tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für den Schlüsselbund für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - BACK_TO_MY_MAC
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.BackToMyMac") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A9 "com.apple.Dataclass.BackToMyMac" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_BACK_TO_MY_MAC=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A9 "com.apple.Dataclass.BackToMyMac" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für den Zugang zu meinem Mac  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_BACK_TO_MY_MAC} == 1 ]; then
					printf "	%b	Zugang zu meinem Mac ist für den Benutzer ${User_gt_500} aktiv via iCloud %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Zugang zu meinem Mac ist für den Benutzer ${User_gt_500} nicht aktiv via iCloud  %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Zugang zu meinem Mac ist für den Benutzer ${User_gt_500} nicht aktiv via iCloud  %s\\n" "${TICK}"	 | tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Zugang zu meinem Mac für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n"	| tee -a ${Audit_file}
	
	###################################################
	# 
	# SYS.2.4.M8 iCloud - FIND_MY_MAC
	#
	###################################################		
		
		if [ $(defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -c "com.apple.Dataclass.DeviceLocator") == 1 ]; then
			local iCoud_Enable_Exits=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A5 "com.apple.Dataclass.DeviceLocator" | grep "Enabled" 2> /dev/null | awk ' { print $3 }' | sed 's/;//' | wc -l`
			local iCoud_FIND_MY_MAC=`defaults read /Users/${User_gt_500}/Library/Preferences/MobileMeAccounts.plist  | grep -B3 -A5 "com.apple.Dataclass.DeviceLocator" | grep "Enabled" | awk ' { print $3 }' | sed 's/;//'`
			
			printf "	%b	überprüfe für den Benutzer ${User_gt_500} die hinterlegten iCloud-Werte für Finde meinen Mac  %s\\n" "${INFO}" | tee -a ${Audit_file}
			if [ ${iCoud_Enable_Exits} == 1 ]; then			
				if [ ${iCoud_FIND_MY_MAC} == 1 ]; then
					printf "	%b	Finde meinen Mac ist für den Benutzer ${User_gt_500} aktiv via iCloud %s\\n" "${CROSS}" | tee -a ${Audit_file}
				else
					printf "	%b	Finde meinen Mac ist für den Benutzer ${User_gt_500} nicht aktiv via iCloud  %s\\n" "${TICK}" | tee -a ${Audit_file}
				fi
			else
				printf "	%b	Finde meinen Mac ist für den Benutzer ${User_gt_500} nicht aktiv via iCloud  %s\\n" "${TICK}" | tee -a ${Audit_file}
			fi	
		else 
			printf "	%b	Keine iCloud-Einstellungen für Finde meinen Mac für den Benutzer ${User_gt_500} gefunden  %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		fi		
		printf "\n" | tee -a ${Audit_file}
	
	
	
	else
		printf "	%b	keine iCloud Einstellungen für den Benutzer ${User_gt_500} gefunden %s\\n" "${TICK}" | tee -a ${Audit_file}
			
	fi
else
	printf "	%b	Die Einstellung für iCloud ist global für den Benutzer ${User_gt_500} nicht vorhanden und somit ist iCloud nicht aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
fi 
printf "\n" | tee -a ${Audit_file}
done < ${Audit_folder}/TMP_User_List_gt_500

}


SYS24M8_AirDrop
sleep 0.5

SYS24M8_iCloud
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
	
###################################################
# 
# SYS.2.4.A9 BSI
#
###################################################

printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A9 Verwendung von zusätzlichen Schutzprogrammen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bei Bedarf, etwa beim Betrieb eines Macs in einem heterogenen Netz, SOLLTEN neben den
	integrierten Schutzmechanismen von macOS zusätzlich Virenschutz-Lösungen von Drittanbietern
	eingesetzt werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}

SYS24M9 ()
{
	printf "	%b	Die Überprüfung muss manuell erfolgen, da es zu viele unterschiedliche Hersteller
		gibt und somit keine vollständige Verifizierung möglich ist. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
}

SYS24M9
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.A10 BSI
#
###################################################

printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A10 Aktivierung der Personal Firewall %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die in macOS integrierte Personal Firewall SOLLTE aktiviert und konfiguriert werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}

###################################################
#
# SYS.2.4.M10 Application Firewall
#
###################################################		

SYS24M10_SOCKET_FILTER_FW ()
{
printf "	%b	überprüfe, ob die Application-Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | awk ' { print $6 }' | sed 's/)//') -ge 1 ]; then
	printf "	%b	Die Application Firewall ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		local Status_logging=`system_profiler SPFirewallDataType | grep "Firewall Logging" | awk ' { print $3 }'`
		local Stealth_Mode=`system_profiler SPFirewallDataType | grep "Stealth Mode" | awk ' { print $3 }'`
		local setting_value=`/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingopt | egrep -o "(detail|brief|throttled)"`
		local get_allow_signed=`/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned`
	
		printf "	%b	Socketfilter Firewall Settings:  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $(system_profiler SPFirewallDataType | grep -B1  "Firewall Logging:" | grep "Mode" | grep -c "Allow all incoming connections") == 1 ]; then
			printf "	%b	Filtermode Mode: Allow all incoming connections  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Filtermode Mode: Disallow all incoming connections  %s\\n" | tee -a ${Audit_file}
		fi	
		printf "	%b	Stealth Mode: "$Stealth_Mode"  %s\\n" | tee -a ${Audit_file}
		
		if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned | grep "Automatically allow signed built-in software" | grep -c "ENABLED") == 1 ]; then
			printf "	%b	Automatically allow signed built-in software: Allowed  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Automatically allow signed built-in software: Disallowed  %s\\n" | tee -a ${Audit_file}
		fi	
		
	
		if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned | grep "Automatically allow downloaded signed software" | grep -c "ENABLED") == 1 ]; then
			printf "	%b	Automatically allow downloaded signed software: Allowed  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Automatically allow downloaded signed software: Disallowed  %s\\n" | tee -a ${Audit_file}
		fi	
	
		
		printf " 	%b	Firewall Logging: "$Status_logging"  %s\\n" | tee -a ${Audit_file}
		
		printf "	%b	überprüfe, welcher Logging Wert für die Socketfilter Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $setting_value == throttled ]; then
			printf "	%b	Für das Logging ist throttled eingestellt. Es sollte detail eingestellt sein. %s\\n" "${CROSS}" | tee -a ${Audit_file};
    	elif [ $setting_value == brief ]; then
			printf "	%b	Für das Logging ist brief eingestellt. Es sollte detail eingestellt sein. %s\\n" "${CROSS}" | tee -a ${Audit_file};
		else
			printf "	%b	Für das Logging ist detail eingestellt %s\\n" "${TICK}" | tee -a ${Audit_file};
        fi
		
		
else
	printf "	%b	Die Application-Firewall ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		
fi
	printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.4.M10 Packet firewall
#
###################################################

SYS24M10_Packet_FILTER_FW ()
{
	
	printf "	%b	überprüfe, ob die Packet-Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}

if [ $(pfctl -s all 2> /dev/null | grep -c "Status: Enabled") == 1 ]; then
	printf "	%b	Die Packet-Firewall ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
	cat /etc/pf.conf >> ${evidence_folder}/SYS24M10_Packet_FILTER_CONFIG
	pfctl -s all 2> /dev/null >> ${evidence_folder}/SYS24M10_Packet_FILTER_STATUS
else
	printf "	%b	Die Packet-Firewall ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		
fi
printf "\n" | tee -a ${Audit_file}
}

SYS24M10_SOCKET_FILTER_FW
sleep 1

SYS24M10_Packet_FILTER_FW
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}

###################################################
# 
# SYS.2.4.A11 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A11 Geräteaussonderung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bei einer Aussonderung des Macs SOLLTE der nichtflüchtige Datenspeicher NVRAM zurückgesetzt werden." | tee -a ${Audit_file}
	printf "\n\n" | tee -a ${Audit_file}
	
	printf "	%b	Folgen Sie den Hinweisen aus Artikel HT204063 von Apple  %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "	%b	Der Link lautet https://support.apple.com/de-de/HT204063 %s\\n" | tee -a ${Audit_file}
	
GEN_SUMMARY_SEPARATOR


###################################################
###################################################
#
#
# BSI - erhohter Schutzbedarf
#
#
###################################################
###################################################

printf %s "\
	Im Folgenden sind für die Bausteine \" SYS.2.4 Clients unter macOS\" und 
	\"SYS.2.1 Allgemeiner Client\" exemplarische Vorschläge für Anforderungen aufgeführt, die 
	über das dem Stand der Technik entsprechende Schutzniveau hinausgehen und BEI ERHÖHTEM 
	SCHUTZBEDARF in Betracht gezogen werden SOLLTEN. Die konkrete Festlegung erfolgt im Rahmen einer
	Risikoanalyse. Die jeweils in Klammern angegebenen Buchstaben zeigen an, welche	Grundwerte durch
	die Anforderung vorrangig geschützt werden (C = Vertraulichkeit, I = Integrität, A = Verfügbarkeit)." | tee -a ${Audit_file}

printf "\n" | tee -a ${Audit_file}

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A28 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A28 Verschlüsselung der Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Wenn vertrauliche Informationen auf den Clients gespeichert werden, SOLLTEN die schutzbedürftigen 
	Dateien, ausgewählte Dateisystembereiche oder besser die gesamte Festplatte verschlüsselt werden. 
	Hierfür SOLLTE ein eigenes Konzept erstellt und die Details der Konfiguration besonders sorgfältig 
	dokumentiert werden, da im Fall von Problemen die Daten auf den verschlüsselten Dateisystemen sonst 
	vollständig verloren sein können. In diesem Zusammenhang SOLLTEN folgende Inhalte geregelt werden: 
	Authentifizierung (z. B. Passwort, PIN, Token), Ablage der Wiederherstellungsinformationen, zu 
	verschlüsselnde Laufwerke, Schreibrechte auf unverschlüsselte Datenträger und wie sichergestellt wird,
	dass die Wiederherstellungsinformationen nur berechtigten Personen zugänglich sind. Auch verschlüsselte 
	Dateien, Partitionen oder Datenträger SOLLTEN regelmäßig gesichert werden. Das verwendete Schlüsselmaterial
	DARF NICHT im Klartext auf den Clients gespeichert sein.

	Benutzer SOLLTEN darüber aufgeklärt werden, wie sie sich bei Verlust eines Authentisierungsmittels zu verhalten haben." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}
	
SYS21M28 ()
{
printf "	%b	Überprüfe, ob die Festplattenverschlüsselung FileVault aktiv ist. %s\\n" "${INFO}" | tee -a ${Audit_file}

FILEVAULTSTATUS=`fdesetup status -extended | grep "FileVault is" | awk ' { print $3 }'`
fdesetup status -extended >> ${evidence_folder}/SYS21M28_File_Vault_Status

if [ ${FILEVAULTSTATUS} == "Off." ]; then
	printf "	%b	Die Festplattenverschlüsselung FileVault ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		else
			printf "	%b	Die Festplattenverschlüsselung FileVault ist aktiv. %s\\n" "${TICK}" | tee -a ${Audit_file}
			
			FILEVAULTVOLUME=`fdesetup status -extended | grep "Volume" | awk ' { print $3 }'`
			
			printf %s "		Es wird als Festplattenvolume genutzt: "${FILEVAULTVOLUME}"" | tee -a ${Audit_file}
			printf "\n" | tee -a ${Audit_file}
			
			sudo fdesetup list >> ${evidence_folder}/SYS21M28_FILE_VAULT_USERS_List
			printf "	%b	Zeige die Kurznamen und UUIDs der freigegebenen FileVault-Benutzer. %s\\n" "${INFO}" | tee -a ${Audit_file}
			while read SYS21M28_FILE_VAULT_USERS
			do
				printf " 		\""${SYS21M28_FILE_VAULT_USERS}"\" \\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS21M28_FILE_VAULT_USERS_List
						
			printf "\n" | tee -a ${Audit_file}
		fi
		printf "\n" | tee -a ${Audit_file}
}

SYS21M28
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A29 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A29 Systemüberwachung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die Clients SOLLTEN in ein geeignetes Systemüberwachungs- bzw. Monitoringkonzept eingebunden werden, 
	das den Systemzustand und die Funktionsfähigkeit der Clients laufend überwacht und Fehlerzustände 
	sowie die Überschreitung definierter Grenzwerte an das Betriebspersonal meldet." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M29 ()
{
cat /etc/syslog.conf >> ${evidence_folder}/SYS21M29_syslog_conf
defaults read /System/Library/LaunchDaemons/com.apple.syslogd.plist >> ${evidence_folder}/SYS21M29_syslogd_plist
cat /etc/asl.conf >> ${evidence_folder}/SYS21M7_asl_conf
defaults read /System/Library/LaunchDaemons/com.apple.newsyslog.plist >> ${evidence_folder}/SYS21M29_newsyslog_plist


printf "	%b	überprüfe, welche globalen Einstellungen für das Logging aktiv sind.  %s\\n" "${INFO}" | tee -a ${Audit_file}
printf "	%b	In der Konfiguration für den Syslog Dienst ist folgendes hinterlegt:  %s\\n" "${INFO}" | tee -a ${Audit_file}
while read SYSLOGCONF
	do
		printf "	%b	${SYSLOGCONF} %s\\n" | tee -a ${Audit_file}		
	
	printf "\n" | tee -a ${Audit_file}
done < ${evidence_folder}/SYS21M29_syslog_conf

if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ]; then
		printf "	%b	Es ist lokales Logging in der Datei syslog.conf aktiviert. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es ist kein lokales Logging in der Datei syslog.conf aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ] &&  [ $(cat /etc/syslog.conf | grep -v "@127.0.0.1" | grep -c "@") != 0 ]; then
		printf "	%b	Es ist zentrales Logging in der Datei syslog.conf aktiviert. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es ist kein zentrales Logging in der Datei syslog.conf aktiviert. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	überprüfe, ob der Dienst Apple System Log für das Logging aktiv ist.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(cat /etc/syslog.conf | grep -c "@127.0.0.1") == 1 ]; then
		printf "	%b	Es wird der Apple System Log Dienst verwendet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	else
		printf "	%b	Es wird der Apple System Log Dienst nicht verwendet. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	überprüfe, welche installierten Anwendungen eine spezielle ASL Konfiguration besitzen.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(ls /etc/asl/ | wc -l) -gt 0 ]; then
		printf "	%b	Nicht alle installierten Anwendungen verwenden die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
		ls /etc/asl/ >> ${evidence_folder}/SYS21M29_Apps_dont_use_default_ASL_config
		printf "	%b	Diese Anwendungen verwenden nicht die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
		while read dont_use_default_ASL_config
			do
				printf "	%b		${dont_use_default_ASL_config} %s\\n" | tee -a ${Audit_file}
				sudo cat /etc/asl/${dont_use_default_ASL_config} >> ${evidence_folder}/SYS21M29_${dont_use_default_ASL_config}	
			done < ${evidence_folder}/SYS21M29_Apps_dont_use_default_ASL_config
	else
		printf "	%b	Alle installierten Anwendungen verwenden die Default Konfiguration von ASL. %s\\n"  | tee -a ${Audit_file}
	fi
printf "\n"| tee -a ${Audit_file}


printf "	%b	Überprüfe den Inhalt vom Pfad /var/log/.  %s\\n" "${INFO}" | tee -a ${Audit_file}
local VAR_LOG_COUNT=`ls /var/log/ | wc -l`
if [ ${VAR_LOG_COUNT} -gt 0 ]; then
		printf "	%b	Im Pfad /var/log/ befinden sich folgende Unterordner oder Dateien: %s\\n"  | tee -a ${Audit_file}
		ls /var/log/ >> ${evidence_folder}/SYS21M29_var_log_entries
		printf "	%b	Die Inhalte der Dateien bzw. Ordner müssen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read var_log_entries
			do
				printf "	%b		${var_log_entries} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M29_var_log_entries
	else
		printf "	%b	Im Pfad /var/log/ befinden sich keine Unterordner oder Dateien. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	Überprüfe den Inhalt vom Pfad /var/log/asl/ und /var/log/asl/logs.  %s\\n" "${INFO}" | tee -a ${Audit_file}
local VAR_LOG_ASL_COUNT=`ls /var/log/ | wc -l`
if [ ${VAR_LOG_ASL_COUNT} -gt 0 ]; then
		printf "	%b	Im Pfad /var/log/asl befinden sich folgende Unterordner oder Dateien: %s\\n"  | tee -a ${Audit_file}
		ls /var/log/asl >> ${evidence_folder}/SYS21M29_var_log_asl_entries
		ls /var/log/asl/logs >> ${evidence_folder}/SYS21M29_var_log_asl_entries
		printf "	%b	Die Inhalte der Dateien bzw. Ordner müssen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read var_log_asl_entries
			do
				printf "	%b		${var_log_asl_entries} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M29_var_log_asl_entries
	else
		printf "	%b	Im Pfad /var/log/ befinden sich keine Unterordner oder Dateien. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

printf "	%b	überprüfe, ob alle installierten Anwendungen den Unified Logging Service verwenden.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(ls /Library/Logs/ | wc -l) -gt 0 ]; then
		printf "	%b	Nicht alle installierten Anwendungen verwenden den Unified Logging Service. %s\\n"  | tee -a ${Audit_file}
		ls /Library/Logs/ >> ${evidence_folder}/SYS21M29_Apps_dont_use_Unified_Logging
		printf "	%b	Für nachfolgend aufgeführten Anwendungen müssen die Logging-Einstellungen manuell geprüft werden. %s\\n"  | tee -a ${Audit_file}
		while read dont_use_Unified_Logging
			do
				printf "	%b		${dont_use_Unified_Logging} %s\\n" | tee -a ${Audit_file}		
			done < ${evidence_folder}/SYS21M29_Apps_dont_use_Unified_Logging
	else
		printf "	%b	Alle installierten Anwendungen verwenden den Unified Logging Service. %s\\n"  | tee -a ${Audit_file}
fi
printf "\n"| tee -a ${Audit_file}

while read User_List_gt_500
	do
		printf "	%b	überprüfe, ob im Benutzerverzeichnis von ${User_List_gt_500} Log-Dateien sind.  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $(ls /Users/${User_List_gt_500}/Library/Logs/ | wc -l) -gt 0 ]; then
			printf "	%b	Es befinden sich Log-Dateien im Benutzerpfad. %s\\n"  | tee -a ${Audit_file}
			ls /Users/${User_List_gt_500}/Library/Logs/ >> ${evidence_folder}/SYS21M29_${User_List_gt_500}_Log-Dateien
			while read USER_LOG_FILES
			do
				printf "	%b		${USER_LOG_FILES} %s\\n" | tee -a ${Audit_file}
			done < ${evidence_folder}/SYS21M29_${User_List_gt_500}_Log-Dateien
		else
			printf "	%b	Es befinden sich keine Log-Dateien im Benutzerpfad. %s\\n"  | tee -a ${Audit_file}
		fi
		printf "\n"| tee -a ${Audit_file}
		done < ${Audit_folder}/TMP_User_List_gt_500
}

SYS21M29
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A30 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A30 Einrichten einer Referenzinstallation für Clients %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Für Clients SOLLTE eine Referenzinstallation erstellt werden, in der die Grundkonfiguration und 
	alle Konfigurationsänderungen, Updates und Patches vor dem Einspielen auf den Clients bei den 
	Anwendern vorab getestet werden können. Darüber hinaus SOLLTE eine solche Referenzinstallation 
	auch dazu genutzt werden, die Clients vereinfacht zu installieren und wieder aufzusetzen, indem 
	eine entsprechend vorkonfigurierte Installation auf geeignete Art und Weise auf die zu 
	installierenden Clients überspielt wird. Für verschiedene typische und häufiger 
	wiederkehrende Testfälle SOLLTEN Checklisten erstellt werden, die beim Testen abgearbeitet werden
	können. Zusätzlich SOLLTEN alle Tests so dokumentiert werden, dass sie zu einem späteren Zeitpunkt
	nachvollzogen werden können." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M30 ()

{
printf "	%b	Sofern das gerade auditierte System nicht den Referenz-Client darstellt, kann keine technische 
		Überprüfung stattfinden. Bitte im Rahmen des Audits das Referenz-System benennen. Dieses bildet 
		auch die Grundlage für eine Umsetzung von Applikation-Whitelisting auf Basis von Profilen.  %s\\n" "${INFO}" | tee -a ${Audit_file}
}

SYS21M30
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A31 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A31 Einrichtung lokaler Paketfilter %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Auf jedem Rechner SOLLTEN, zusätzlich zu den eingesetzten zentralen Sicherheitsgateways, lokale 
	Paketfilter eingesetzt werden. Als Strategie zur Paketfilter-Implementierung SOLLTE eine 
	Whitelist-Strategie gewählt werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

###################################################
#
# SYS21M31 Application Firewall
#
###################################################		

SYS21M31_SOCKET_FILTER_FW ()
{
printf "	%b	überprüfe, ob die Application-Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | awk ' { print $6 }' | sed 's/)//') -ge 1 ]; then
	printf "	%b	Die Application Firewall ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		
		local Status_logging=`system_profiler SPFirewallDataType | grep "Firewall Logging" | awk ' { print $3 }'`
		local Stealth_Mode=`system_profiler SPFirewallDataType | grep "Stealth Mode" | awk ' { print $3 }'`
		local setting_value=`/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingopt | egrep -o "(detail|brief|throttled)"`
		local get_allow_signed=`/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned`
	
		printf "	%b	Socketfilter Firewall Settings:  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $(system_profiler SPFirewallDataType | grep -B1  "Firewall Logging:" | grep "Mode" | grep -c "Allow all incoming connections") == 1 ]; then
			printf "	%b	Filtermode Mode: Allow all incoming connections  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Filtermode Mode: Disallow all incoming connections  %s\\n" | tee -a ${Audit_file}
		fi	
		printf "	%b	Stealth Mode: "$Stealth_Mode"  %s\\n" | tee -a ${Audit_file}
		
		if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned | grep "Automatically allow signed built-in software" | grep -c "ENABLED") == 1 ]; then
			printf "	%b	Automatically allow signed built-in software: Allowed  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Automatically allow signed built-in software: Disallowed  %s\\n" | tee -a ${Audit_file}
		fi	
		
	
		if [ $(/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned | grep "Automatically allow downloaded signed software" | grep -c "ENABLED") == 1 ]; then
			printf "	%b	Automatically allow downloaded signed software: Allowed  %s\\n" | tee -a ${Audit_file}
		else
			printf "	%b	Automatically allow downloaded signed software: Disallowed  %s\\n" | tee -a ${Audit_file}
		fi	
	
		
		printf " 	%b	Firewall Logging: "$Status_logging"  %s\\n" | tee -a ${Audit_file}
		
		printf "	%b	überprüfe, welcher Logging Wert für die Socketfilter Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}
		if [ $setting_value == throttled ]; then
			printf "	%b	Für das Logging ist throttled eingestellt. Es sollte detail eingestellt sein. %s\\n" "${CROSS}" | tee -a ${Audit_file};
    	elif [ $setting_value == brief ]; then
			printf "	%b	Für das Logging ist brief eingestellt. Es sollte detail eingestellt sein. %s\\n" "${CROSS}" | tee -a ${Audit_file};
		else
			printf "	%b	Für das Logging ist detail eingestellt %s\\n" "${TICK}" | tee -a ${Audit_file};
        fi
		
		
else
	printf "	%b	Die Application-Firewall ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		
fi
	printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS21M31 Packet firewall
#
###################################################

SYS21M31_Packet_FILTER_FW ()
{
	
	printf "	%b	überprüfe, ob die Packet-Firewall von macOS aktiv ist  %s\\n" "${INFO}" | tee -a ${Audit_file}

if [ $(pfctl -s all 2> /dev/null | grep -c "Status: Enabled") == 1 ]; then
	printf "	%b	Die Packet-Firewall ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
	cat /etc/pf.conf >> ${evidence_folder}/SYS21M31_Packet_FILTER_CONFIG
	pfctl -s all 2> /dev/null >> ${evidence_folder}/SYS21M31_Packet_FILTER_STATUS
else
	printf "	%b	Die Packet-Firewall ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
		
fi
printf "\n" | tee -a ${Audit_file}
}

SYS21M31_SOCKET_FILTER_FW
sleep 1

SYS21M31_Packet_FILTER_FW
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A32 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A32 Einsatz zusätzlicher Maßnahmen zum Schutz vor Exploits %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Auf dem IT-System SOLLTEN zusätzliche Maßnahmen zum expliziten Schutz vor Exploits 
	(Angriffe, um Systemlücken auszunutzen) getroffen werden. Wenn notwendige Schutzmaßnahmen
	nicht mit Bordmitteln erfüllt werden können, SOLLTEN zusätzliche geeignete Sicherheitsprodukte 
	eingesetzt werden. Sollte es nicht möglich sein, entsprechende Maßnahmen mit Bordmitteln oder
	einem geeigneten Sicherheitsprodukt umzusetzen, SOLLTEN andere geeignete (in der Regel 
	organisatorische) Sicherheitsmaßnahmen ergriffen werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

###################################################
# 
# SYS.2.1.M32 SIP Status
#
###################################################

SYS21M32_SIP ()
{
printf "	%b	Überprüfung des System Integrity Protection (SIP) Status %s\\n" "${INFO}" | tee -a ${Audit_file}
SIPSTATUS=`csrutil status 2> /dev/null |  awk ' { print $5 }'`

csrutil status 2> /dev/null >> ${evidence_folder}/SYS21M32_System_Integrity_Status

if [ ${SIPSTATUS} == "enabled." ]; then
	printf "	%b	System Integrity Protection (SIP) ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	System Integrity Protection (SIP) ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi

printf "\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M32 Xprotect Status
#
###################################################

SYS21M32_Xprotect ()
{
printf "	%b	Überprüfung des Xprotect Status %s\\n" "${INFO}" | tee -a ${Audit_file}

defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist 2> /dev/null >> ${evidence_folder}/SYS21M32_XProtect

if [[ ${OS_vers_major} -eq 10 ]] && [[ ${OS_vers_minor} -gt 9 ]]; then

  last_xprotect_update_epoch_time=$(printf "%s\n" `for i in $(pkgutil --pkgs=".*XProtect.*"); do pkgutil --pkg-info $i | awk '/install-time/ {print $2}'; done` | sort -n | tail -1)
  last_xprotect_update_human_readable_time=`/bin/date -r "$last_xprotect_update_epoch_time" '+%d.%m.%Y %H:%M:%S'`
  XPROTECTCHECKRESULT="$last_xprotect_update_human_readable_time"
  printf " 		Die letzte Xprotect Änderung erfolgte am "${XPROTECTCHECKRESULT}"\\n" | tee -a ${Audit_file}
  
fi


printf "\n\n" | tee -a ${Audit_file}
}

###################################################
# 
# SYS.2.1.M32 Gatekeeper Status
#
###################################################

SYS21M32_Gatekeeper ()
{
printf "	%b	Überprüfung des Gatekeeper Status %s\\n" "${INFO}" | tee -a ${Audit_file}

GATEKEEPERSTATUS=`spctl --status 2> /dev/null |  awk ' { print $2 }'`
spctl --status 2> /dev/null >> ${evidence_folder}/SYS21M32_Gatekeeper

if [ ${GATEKEEPERSTATUS} == "enabled" ]; then
	printf "	%b	Gatekeeper ist aktiv %s\\n" "${TICK}" | tee -a ${Audit_file}
		else
			printf "	%b	Gatekeeper ist nicht aktiv %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
}

SYS21M32_SIP
sleep 1

SYS21M32_Xprotect
sleep 1

SYS21M32_Gatekeeper
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A33 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A33 Application Whitelisting %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE über Application Whitelisting sichergestellt werden, dass nur erlaubte Programme und 
	Skripte ausgeführt werden. Die Regeln SOLLTEN so eng wie möglich gefasst werden. Falls Pfade 
	und Hashes nicht explizit angegeben werden können, SOLLTEN alternativ auch zertifikatsbasierte 
	oder Pfad-Regeln genutzt werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M33 ()

{
printf "	%b	Application-Whitelisting unter macOS kann über unterschiedliche Wege implementiert werden.
		Parental-Control mehr Informationen siehe Link https://support.apple.com/de-de/guide/mac-help/mtusr004/mac
		MDM-Profiles mehr Informationen siehe Link https://support.apple.com/de-de/macos/server
		der Lösung Santa mehr Informationen siehe Link https://santa.readthedocs.io/en/latest/
		%s\\n" "${INFO}" | tee -a ${Audit_file}
		
printf "	%b	Überprüfe, ob via Profilmanager das System ${MODELIDENTIFIER} verwaltet wird.  %s\\n" "${INFO}" | tee -a ${Audit_file}
if [ $(system_profiler SPConfigurationProfileDataType | wc -l) -gt 0 ] ; then

	system_profiler SPConfigurationProfileDataType >> ${evidence_folder}/SYS21M33_SPConfigurationProfileDataType
	system_profiler SPManagedClientDataType >> ${evidence_folder}/SYS21M33_SPManagedClientDataType
	
	if [ -e /Library/Managed\ Preferences/com.apple.applicationaccess.plist ]; then
		defaults read  /Library/Managed\ Preferences/com.apple.applicationaccess.plist >> ${evidence_folder}/SYS21M33_com_apple_applicationaccess_plist
	fi
	
	printf "	%b	Das System ${MODELIDENTIFIER} wird mittels Profilen verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
	printf "	%b	Überprüfe, ob via Profilmanager ein Whitelisting von Applications erfolgt.  %s\\n" "${INFO}" | tee -a ${Audit_file}
	
	
	if [ -e /Library/Managed\ Preferences/com.apple.applicationaccess.new.plist ]; then
		defaults read  /Library/Managed\ Preferences/com.apple.applicationaccess.new.plist >> ${evidence_folder}/SYS21M33_com_apple_applicationaccess_new_plist
		if [ $(grep -c "whiteList" ${evidence_folder}/SYS21M33_com_apple_applicationaccess_new_plist) -gt 0 ] ; then
			printf "	%b	Applications werden mittels whitelist verwaltet. %s\\n" "${TICK}" | tee -a ${Audit_file}
			printf "	%b	Überprüfe, wie viele Applications freigegeben sind.  %s\\n" "${INFO}" | tee -a ${Audit_file}
			printf "	%b	Es sind per Whitelisting insgesamt $(grep -c "displayName" ${evidence_folder}/SYS21M33_com_apple_applicationaccess_new_plist) Applications freigegeben. %s\\n" | tee -a ${Audit_file}
			
		else
			printf "	%b	Es werden keine Applications mittels whitelisting verwaltet. %s\\n" "${CROSS}" | tee -a ${Audit_file}
			printf "	%b	Sofern alternative Lösungen eingesetzt werden, sollte die Dokumentation übergeben werden. %s\\n" "${INFO}" | tee -a ${Audit_file}			
		fi
	fi
	
else
	printf "	%b	Es ist kein Profilemanager hinterlegt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
fi
	printf "\n"| tee -a ${Audit_file}
}

SYS21M33
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


#################################################
# 
# SYS.2.1.A34 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A34 Einsatz von Anwendungsisolation %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Anwendungen, mit denen externe Daten bearbeitet werden, SOLLTEN ausschließlich in einer vom 
	Betriebssystem isolierten Ablaufumgebung betrieben werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M34 ()

{
	printf "	%b	Application aus dem App-Store werden per default in einer Sandbox betrieben. %s\\n" "${INFO}" | tee -a ${Audit_file}
	printf "	%b	Überprüfe, welche Applicationen aus dem App-Store heruntergeladen wurden. %s\\n" "${INFO}" | tee -a ${Audit_file}
	find /Applications -path '*Contents/_MASReceipt/receipt' -maxdepth 4 -print | sed 's#.app/Contents/_MASReceipt/receipt#.app#g; s#/Applications/##' 2> /dev/null >> ${evidence_folder}/SYS21M34_Apps_from_App_Store
	printf "	%b	Folgende Apps werden in der Sandbox betrieben: %s\\n" "${TICK}" | tee -a ${Audit_file}
	while read Apps_from_App_Store
	do
			printf "	%b		${Apps_from_App_Store} %s\\n" | tee -a ${Audit_file}
	done < ${evidence_folder}/SYS21M34_Apps_from_App_Store
	
	printf "\n"| tee -a ${Audit_file}
	
	printf "	%b	Eine weitere Möglichkeit, zu überprüfen, ob die Application in der Sandbox 
		betrieben wird ist, den Befehl asctl sandbox check --pid XYZ auszuführen. Wobei 
		XYZ die PID (Process ID) der Anwendung ist, welche überprüft werden soll. %s\\n" "${INFO}" | tee -a ${Audit_file}	
	
		printf "	%b	Überprüfe, pro Benutzer welche sandboxed Apps zur Verfügung stehen. %s\\n" "${INFO}" | tee -a ${Audit_file}	
		
		dscl . list /Users UniqueID | awk '$2 > 500 { print $1 }' >> ${evidence_folder}/SYS21M2_User_List_gt_500

		while read USER_gt_500
		do
			ls /Users/${USER_gt_500}/Library/Containers/ 2> /dev/null >> ${evidence_folder}/SYS21M34_User_${USER_gt_500}_sanboxed_apps
			printf "	%b		Dem Benutzer \""${USER_gt_500}"\" stehen folgende sandboxed Apps zur Verfügung: %s\\n" | tee -a ${Audit_file}
				
				while read sanboxed_apps
				do
					printf "	%b		${sanboxed_apps} %s\\n" | tee -a ${Audit_file}
				done < ${evidence_folder}/SYS21M34_User_${USER_gt_500}_sanboxed_apps
		
			printf "\n"| tee -a ${Audit_file}
		done < ${evidence_folder}/SYS21M2_User_List_gt_500
	
printf "\n" | tee -a ${Audit_file}
}


SYS21M34
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A35 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A35 Aktive Verwaltung der Wurzelzertifikate %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Im Zuge der Beschaffung und Installation des Clients SOLLTE dokumentiert werden, welche 
	Wurzelzertifikate für den Betrieb des Clients notwendig sind. Auf dem Client SOLLTEN 
	lediglich die für den Betrieb notwendigen und vorab dokumentierten Wurzelzertifikate 
	enthalten sein. Es SOLLTE regelmäßig überprüft werden, ob die vorhandenen Wurzelzertifikate 
	noch den Vorgaben der Institution entsprechen. Es SOLLTEN alle auf dem IT-System vorhandenen 
	Zertifikatsspeicher in die Prüfung einbezogen werden (z.B. UEFI-Zertifikatsspeicher, 
	Zertifikatsspeicher von Web-Browsern etc.)." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M35 ()

{
	printf "	%b	Die Dokumentation der Beschaffung und Installation des Clients kann nicht 
		technisch geprüft werden. Dies muss im Rahmen der Dokumentenlenkung erfolgen. Die 
		Webseite https://support.apple.com/de-de/HT202858 listet die vertrauenswürdigen 
		Root-Zertifikate auf.	%s\\n" "${INFO}" | tee -a ${Audit_file}
}

SYS21M35
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A36 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A36 Selbstverwalteter Einsatz von SecureBoot und TPM %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Auf UEFI-kompatiblen Systemen SOLLTEN Bootloader, Kernel sowie alle benötigten Firmware-Komponenten 
	durch selbstkontrolliertes Schlüsselmaterial signiert und nicht benötigtes Schlüsselmaterial entfernt
	werden. Sofern das TPM nicht benötigt wird, SOLLTE es deaktiviert werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M36 ()

{
		printf "	%b	Apples bislang optionaler Notarisierungsdienst ist nun für bestimmte Software zur 
		Pflicht geworden: Ab macOS Mojave 10.14.5 werden per Developer-ID signierte Apps von neuen 
		Entwicklern nur dann vom Betriebssystem ausgeführt, wenn sie vorab vom Mac-Hersteller beglaubigt 
		wurden. Dies gilt zugleich auch für neue sowie aktualisierte Kernel-Extensions (Kexts), wie Apple
		kurzfristig vorab bekanntgegeben hatte.	%s\\n" "${INFO}" | tee -a ${Audit_file}
}

SYS21M36
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A37 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A37 Schutz vor unbefugten Anmeldungen %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Um einen Zugang zum System durch kompromittierte Anmeldeinformationen zu verhindern, SOLLTE eine
	Mehrfaktorauthentisierung verwendet werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M37 ()

{
	printf "	%b	Dies ist eine Einstellung der Apple-ID. Bitte überprüfen Sie Ihr Apple-Konto. %s\\n" "${ATTENTION}" | tee -a ${Audit_file}
}

SYS21M37
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A38 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A38 Einbindung in die Notfallplanung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die Clients SOLLTEN im Notfallmanagementprozess berücksichtigt werden. Die Clients sind anhand der 
	Geschäftsprozesse, für die sie benötigt werden, für den Wiederanlauf zu priorisieren. 
	Es SOLLTEN geeignete Notfallmaßnahmen vorgesehen werden, indem mindestens Wiederanlaufpläne erstellt,
	Bootmedien zur Systemwiederherstellung generiert sowie Passwörter und kryptografische Schlüssel sicher 
	hinterlegt werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M38 ()

{
	printf "	%b	Bitte beim Notfallmanagement erfragen, in welchem Dokument dies geregelt wird und für 
		diese Überprüfung angeben. Zusätzlich sollten die Dokumente für den Wiederanlauf und die 
		Wiederanlaufkoordination hinzugefügt werden. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M38
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A39 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A39 Unterbrechungsfreie und stabile Stromversorgung %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Bei erhöhten Anforderungen an die Verfügbarkeit von stationären Clients SOLLTEN diese an eine 
	unterbrechungsfreie Stromversorgung (USV) angeschlossen werden. Die USV SOLLTE hinsichtlich 
	Leistung und Stützzeit ausreichend dimensioniert sein. Wenn Änderungen an den Verbrauchern 
	durchgeführt wurden, SOLLTE erneut geprüft werden, ob die Stützzeit ausreichend ist. Sowohl 
	für die USV-Geräte als auch die Clients SOLLTE ein Überspannungsschutz vorhanden sein.

	Die tatsächliche Kapazität der Batterie und damit die Stützzeit der USV SOLLTE regelmäßig 
	getestet werden. Die USV SOLLTE regelmäßig gewartet werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M39 ()

{
	printf "	%b	Bitte bei den Verantwortlichen für das Gebäudemanagement nachfragen, ob die 
		genutzten Stromanschlüsse durch eine USV mit abgesichert sind. Da hier kann keine technische 
		Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M39
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A40 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A40 Betriebsdokumentation %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Die Durchführung betrieblicher Aufgaben an Clients SOLLTE nachvollziehbar dokumentiert werden 
	(Wer?, Wann?, Was?), vor allem wenn dies Gruppen von Clients betrifft. Aus der Dokumentation 
	SOLLTEN insbesondere Konfigurationsänderungen nachvollziehbar sein, auch sicherheitsrelevanten 
	Aufgaben (wer ist z. B. befugt, neue Festplatten einzubauen) SOLLTEN dokumentiert werden. Alles,
	was automatisch dokumentiert werden kann, SOLLTE auch automatisch dokumentiert werden. Die 
	Dokumentation SOLLTE gegen unbefugten Zugriff und Verlust geschützt werden." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M40 ()

{
	printf "	%b	Bitte das Infrastruktur- und Betriebsführungskonzept sowie Betriebshanbücher für dieses
		System angeben. Da hier kann keine technische Prüfung erfolgen kann. %s\\n" "${INFO}"	 | tee -a ${Audit_file}
}

SYS21M40
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}


################################################
# 
# SYS.2.1.A41 BSI
#
###################################################
printf "%b Die nachfolgende Anforderung gehört zum BSI Baustein SYS.2.1 Allgemeiner Client %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.1.A41 Verhinderung der Überlastung der lokalen Festplatte %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Es SOLLTE überlegt werden, Quotas einzurichten. Alternativ SOLLTEN Mechanismen des verwendeten 
	Datei- oder Betriebssystemsystems genutzt werden, die die Benutzer bei einem bestimmten 
	Füllstand der Festplatte warnen oder nur noch dem Systemadministrator Schreibrechte einräumen." | tee -a ${Audit_file}

	printf "\n\n"| tee -a ${Audit_file}

SYS21M41 ()

{
	printf "	%b	Die Quota-Optionsdatei zur Aktivierung dieser Option sind versteckte Dateien, die 
		sich im Stammverzeichnis befinden und dem macOS-System mitteilen, dass es Quoten auf diesem 
		Dateisystem aktivieren soll. Die Quota-Dateien sind nicht per Default im System vorhanden. 
		Überprüfe, ob folgende versteckte Datei vorhanden sind:
			.quota.ops.user
			.quota.ops.group	%s\\n" "${INFO}"	 | tee -a ${Audit_file}
			
	if [ $(ls -la / | egrep -wc '.quota.ops.group|.quota.ops.user') == 1 ]; then
		sudo repquota -a -v >> ${evidence_folder}/SYS21M41_disk_quota
		printf "	%b	Für die komplette primäre Festplatte sind Quotas gesetzt. %s\\n" "${TICK}" | tee -a ${Audit_file}
		printf "	%b	Die derzeitigen Quotas sind in der Datie SYS21M41_disk_quota im Verzeichnis
		${evidence_folder} aufgeführt. %s\\n" "${INFO}" | tee -a ${Audit_file}		
	else
		printf "	%b	Es sind keine Quotas für die komplette primäre Festplatte gesetzt. %s\\n" "${CROSS}" | tee -a ${Audit_file}
	fi
	printf "\n"| tee -a ${Audit_file}
}

SYS21M41
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}



###################################################
# 
# SYS.2.4.A11 BSI
#
###################################################
printf "%b Diese Anforderung gehört zum BSI Baustein SYS.2.4 Clients unter macOS %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf "%b SYS.2.4.A12 Aktivieren des Firmware-Kennworts (CI) %s\\n" "${AUDIT}" | tee -a ${Audit_file}
printf %s "\
	Um ein unberechtigtes Booten des Macs von einem anderen Startlaufwerk zu verhindern, SOLLTE die
	Abfrage eines sicheren Firmware-Kennworts des Macs im sogenannten \"Command-Modus\" aktiviert werden.
	Es SOLLTE geprüft werden, ob über den \"Full-Modus\" ein Kennwort bei jedem Startvorgang abgefragt
	werden sollte." | tee -a ${Audit_file}
printf "\n\n" | tee -a ${Audit_file}

SYS24M11 ()
{
printf "	%b	überprüfe, ob das EFI-Passwort unter macOS aktiv und auf den Wert \"Full-Modus\" gesetzt ist.  %s\\n" "${INFO}" | tee -a ${Audit_file}

sudo firmwarepasswd -verify 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_verify

if [ $(sudo firmwarepasswd -verify 2> /dev/null | grep -c "No firmware password set") == 1 ]; then
	printf "	%b	Das EFI-Passwort ist nicht gesetzt %s\\n" "${CROSS}" | tee -a ${Audit_file}
else
	printf "	%b	Das EFI-Passwort ist gesetzt %s\\n" "${TICK}" | tee -a ${Audit_file}
    sudo firmwarepasswd -mode 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_mode
    sudo firmwarepasswd -check 2> /dev/null >> ${evidence_folder}/SYS24M11_EFI_Password_check
fi
printf "\n" | tee -a ${Audit_file}
}

SYS24M11
sleep 1

GEN_SUMMARY_SEPARATOR | tee -a ${Audit_file}
