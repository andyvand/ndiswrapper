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
#include <stdio.h>
#include <string.h>

#include "loaddriver.h"

/* undefine YY_NULL and define as nothing to make a void YY_DECL */
#undef YY_NULL
#define YY_NULL
#define YY_DECL void inf_lex()

void parse_setting(char *text);
void parse_device(char *text);
static char name[80];

%}

%s FoundVersion
%s FoundManufacturer
%s FoundDevices
%s FoundCommonSettings
%s FoundRegSetting
%s FoundSettingName
%s NeedSettingValue
%s FoundSettingValue

StartHeading \[
VersionHeading version\]
ManufacturerHeading Manufacturer\]
CommonSettingsHeading common\.reg\]
UnknownHeading [a-zA-Z0-9\.]+\]
SettingNamePrefix HKR,[[:space:]]*Ndi\\params\\
SettingName [^,]+
SettingValuePrefix [\t ]*,[\t ]*default[\t ]*,[^,]*,[\t ]*\"
SettingValue [^\"]*\"

%%

{StartHeading} BEGIN(INITIAL);

{VersionHeading} BEGIN(FoundVersion);
<FoundVersion>Provider[[:space:]]*=[[:space:]]*.* parse_setting(yytext);
<FoundVersion>DriverVer=.* parse_setting(yytext);

{ManufacturerHeading} BEGIN(FoundManufacturer);
<FoundManufacturer>[ \t].*=.* parse_setting(yytext + 1);

 /* FoundDevices can only be set by a call to found_heading returning FOUND_DEVICES */
<FoundDevices>[ \t].*=.* parse_device(yytext + 1);

 /* The following lines parse out settings from the common.reg portion of the .inf */
{CommonSettingsHeading}                  BEGIN(FoundCommonSettings);
<FoundCommonSettings>{SettingNamePrefix} BEGIN(FoundSettingName);
<FoundSettingName>{SettingName}          { strncpy(name, yytext, 80); BEGIN(NeedSettingValue); }
<NeedSettingValue>{SettingValuePrefix}   BEGIN(FoundSettingValue);
<NeedSettingValue>.                      BEGIN(FoundCommonSettings);
<FoundSettingValue>{SettingValue}        { yytext[yyleng - 1] = '\0'; found_setting(name, yytext); BEGIN(FoundCommonSettings); }

{UnknownHeading} {
    /* drop the ] from the heading before passing it to found_heading */
    yytext[yyleng - 1] = '\0';

    switch(found_heading(yytext))
    {
    case FOUND_DEVICES:
        BEGIN(FoundDevices);
        break;
    }
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

/* helper function to trim off the spaces on the right of the text */
void trim_right(char *text)
{
    unsigned int len;
    for(len = strlen(text) - 1; len >= 0; len--)
		if (text[len] != ' ' &&
			text[len] != '\t' &&
			text[len] != '\r' &&
			text[len] != '\n')
		    break;
		else
		    text[len] = '\0';
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

		trim_right(text);
		trim_right(value);
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
				if (sscanf(device_str, "%x", &device) == 1)
				    found_pci_id(vendor, device);
			}
		}
	}
}
