#############################################################################/##
# OpenVAS Vulnerability Test
# $Id: gb_seamonkey_rsa_spoof_vuln_sep14_macosx.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Mozilla Seamonkey RSA Spoof Vulnerability September14 (Macosx)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804926");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-30 09:51:51 +0530 (Tue, 30 Sep 2014)");

  script_name("Seamonkey RSA Spoof Vulnerability September14 (Macosx)");

  script_tag(name:"summary", value:"This host is installed with Mozilla Seamonkey
  and is prone to spoof vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla SeaMonkey before 2.29.1 on Macosx");

  script_tag(name:"solution", value:"Upgrade to Mozilla seamonkey version 2.29.1
  or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61540");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1069405");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-73.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/seamonkey");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version: "2.29.1"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
