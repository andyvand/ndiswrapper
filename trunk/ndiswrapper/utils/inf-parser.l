%option nounput noyywrap

%{
/*
 *  Copyright (C) 2003 Joseph Dunn
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "loaddriver.h"

#define INVALID_PCI_ID 0xFFFF

/* TODO: check for valid signatures???  "$CHICAGO$" "$Windows NT$" */

/* undefine YY_NULL and define as nothing to make a void YY_DECL */
#undef YY_NULL
#define YY_NULL
#define YY_DECL void inf_lex()

void parse_setting(char *text);
void parse_device(char *text);
static char name[80];

/* helper function to trim off the spaces on the right of the text */
char* trim_ends(char *text)
{
    unsigned int len;
    for(; text[0] != '\0'; text++)
		if (text[0] != ' ' &&
			text[0] != '\t' &&
			text[0] != '\r' &&
			text[0] != '\n')
		    break;

    for(len = strlen(text) - 1; len >= 0; len--)
		if (text[len] != ' ' &&
			text[len] != '\t' &&
			text[len] != '\r' &&
			text[len] != '\n')
		    break;
		else
		    text[len] = '\0';
   return text;
}

static char **deviceHeaders = NULL;

static void removeDeviceHeader(int index)
{
    int x;
    for(x = 0; deviceHeaders[x] != NULL; x++)
		/*intentionally blank*/;
	x--;

	free(deviceHeaders[index]);

    if (x == index)
	    deviceHeaders[index] = NULL;
	else
        memmove(deviceHeaders + index, deviceHeaders + index + 1, sizeof(char*) * (x - index + 1));
}

static void setManufacturerStr(char *text)
{
    int x, count = 1, kept = 0, foundXP = 0, foundNT = 0;
    char *temp = text;

    for(x = 0; text[x] != '\0'; x++)
		if (text[x] == ',')
        {
		    text[x] = '\0';
		    count++;
        }
    deviceHeaders = (char**)malloc(sizeof(char*) * (count + 1));
	deviceHeaders[0] = strdup(text);
	deviceHeaders[count] = NULL;
	kept = 1;

	for(x = 1; x < count; x++)
	{
	    temp += strlen(temp) + 1;
		if (strcmp(temp, "NT.5.1") == 0)
		    foundXP = 1;
		else if (strcmp(temp, "NT") == 0)
		    foundNT = 1;

		if (strcmp(temp, "ME") != 0)
		{
	        deviceHeaders[kept] = (char*)malloc(sizeof(char) * (strlen(text) + strlen(temp) + 2));
		    sprintf(deviceHeaders[kept], "%s.%s", text, temp);
			kept++;
		}
    }

	if (foundXP || foundNT)
    {
	    removeDeviceHeader(0);
		count--;

		if (foundXP)
	        for(x = 0; x < count; x++)
			    if (strcmp(deviceHeaders[x] + strlen(deviceHeaders[x]) - 3, ".NT") == 0)
				{
				    removeDeviceHeader(x);
					break;
                }
    }
}

static int isDeviceSection(char *heading)
{
    int x;
	if (deviceHeaders != NULL)
    	for(x = 0; deviceHeaders[x] != NULL; x++)
		    if (strcmp(heading, deviceHeaders[x]) == 0)
			    return 1;
    return 0;
}

static char **settingsHeaders = NULL;

static void addSettingsSections(char *name)
{
    int x = 0;
    char *next;

#ifdef DEBUG
	if (settingsHeaders != NULL)
	{
	    for(x = 0; settingsHeaders[x] != NULL; x++)
		    printf("prelist settings: %s\n", settingsHeaders[x]);
		printf("\n");
	}
#endif

	do
	{
	    next = strchr(name, ',');
		if (next != NULL)
		{
		    next[0] = '\0';
			next++;
		}

		name = trim_ends(name);
		if (settingsHeaders == NULL)
		{
	        settingsHeaders = (char**)malloc(sizeof(char*));
			settingsHeaders[0] = NULL;
		}
		for(x = 0; settingsHeaders[x] != NULL; x++)
            if (strcmp(name, settingsHeaders[x]) == 0)
                break;

    	if (settingsHeaders[x] == NULL)
	    {
            settingsHeaders = realloc(settingsHeaders, sizeof(char*) * (x + 2));
			/* broadcom hack */
			if (strcmp(name, "BCM43XX") == 0)
			    settingsHeaders[x] = strdup("BCM43XX.NT");
			else
			    settingsHeaders[x] = strdup(name);
			settingsHeaders[x + 1] = NULL;

#ifdef DEBUG
			printf("Added settings section:%s\n", settingsHeaders[x]);
#endif
        }

		name = next;
    } while(name != NULL);

#ifdef DEBUG
	for(x = 0; settingsHeaders[x] != NULL; x++)
	    printf("list settings: %s\n", settingsHeaders[x]);
	printf("\n");
#endif
}

static int isSettingsSection(char *name)
{
    int x;
	if (settingsHeaders != NULL)
        for(x = 0; settingsHeaders[x] != NULL; x++)
		    if (strcmp(name, settingsHeaders[x]) == 0)
		        return 1;
    return 0;
}

typedef int id[2];
static id *knownIds = NULL;

static int addPciId(int vendor, int device)
{
    int x = 0, retval = 0;

	if (knownIds == NULL)
    {
	    knownIds = (id*)malloc(sizeof(id));
        knownIds[0][0] = INVALID_PCI_ID;
    }
    for(x = 0; knownIds[x][0] != INVALID_PCI_ID; x++)
        if (knownIds[x][0] == vendor &&
			knownIds[x][1] == device)
            break;

	if (knownIds[x][0] == INVALID_PCI_ID)
	{
        knownIds = realloc(knownIds, sizeof(id) * (x + 2));
		knownIds[x][0] = vendor;
		knownIds[x][1] = device;
		knownIds[x + 1][0] = INVALID_PCI_ID;
		retval = 1;
    }

	return retval;
}

%}

%s VersionSection
%s ManufacturerSection
%s DeviceSection
%s SettingsSection
%s FoundAddReg
%s FoundRegSetting
%s FoundSetting
%s NeedValue
%s FoundValue

%%

 /* throw away comment-only lines */
[ \t]*;.* ;

\[version\]                        BEGIN(VersionSection);
<VersionSection>DriverVer[\t ]*=.* parse_setting(yytext);

 /* Find the manufacturer string (given the string table we could confirm the provider) */
\[Manufacturer\]                    BEGIN(ManufacturerSection);
<ManufacturerSection>[^=\n]+=[ \t]* ;
<ManufacturerSection>[^= \t\r\n]+   { setManufacturerStr(yytext); BEGIN(INITIAL); }

 /* DeviceSection can only be set by a call to found_heading returning FOUND_DEVICES */
<DeviceSection>[^=\n]+=[ \t]+    ;
<DeviceSection>[^ \t&=,\r\n\[]+  addSettingsSections(yytext);
<DeviceSection>,[ \t]+           ;
<DeviceSection>PCI\\VEN[^ \t\n]+ parse_device(yytext);

<SettingsSection>AddReg[ \t]*=[ \t]*        BEGIN(FoundAddReg);
<FoundAddReg>[^=\n]+[ \t]*                  { addSettingsSections(yytext); BEGIN(INITIAL); }
<SettingsSection>HKR,[ \t]*Ndi\\[Pp]arams\\ BEGIN(FoundSetting);
<FoundSetting>[^, \t\n]+                    { strncpy(name, yytext, 80); BEGIN(NeedValue); }

<NeedValue>[ \t]*,[ \t]*[dD]efault[ \t]*,[^,\n]*,[ \t]* BEGIN(FoundValue);
<NeedValue>[ \t]*,[^,\n]*,[^,\n]*,[ \t]*                BEGIN(SettingsSection);

<FoundValue>\"[^\"\n]*\" { yytext[strlen(yytext) - 1] = '\0'; found_setting(name, yytext + 1); BEGIN(SettingsSection); }

\[[^ \t\n]+\] {
    /* drop the ] from the heading before passing it to found_heading */
    yytext[yyleng - 1] = '\0';

    if (isDeviceSection(yytext + 1))
        BEGIN(DeviceSection);
	else if (isSettingsSection(yytext + 1))
	    BEGIN(SettingsSection);
    else
		BEGIN(INITIAL);
}

 /* Drop unrecognized stuff on the floor */
\n
.

%%

/* This function is called to parse the input file (i.e. the inf) */
void read_inf(FILE *input)
{
    yyin = input;
    inf_lex();
}

/* parse the setting name and value from a settings line */
void parse_setting(char *text)
{
    char *value;
    value = strchr(text, '=');
    if (value != NULL)
    {
        value[0] = '\0';
        for(value++; *value == ' '; value++)
			/* intentionally left blank */;

		text = trim_ends(text);
		value = trim_ends(value);
        found_setting(text, value);
    }
}

/* parse device ids from the inf line */
void parse_device(char *text)
{
    char *vendor_str;
	vendor_str = strstr(text, "\\VEN_");
	if (vendor_str != NULL)
    {
        char *device_str;
        vendor_str += 5;
		device_str = strstr(vendor_str, "&DEV_");
		if (device_str != NULL)
		{
		    unsigned int vendor;
		    device_str += 5;
			if (sscanf(vendor_str, "%x", &vendor) == 1)
			{
		        unsigned int device;
				if (sscanf(device_str, "%x", &device) == 1 &&
				    addPciId(vendor, device))
				    found_pci_id(vendor, device);
			}
		}
	}
}
