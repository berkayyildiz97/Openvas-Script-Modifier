###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Reader Out-of-bounds Vulnerability Feb15 (Mac OS X)
#
# Authors:
# Rinu <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805439");
  script_version("2019-07-05T08:56:43+0000");
  script_cve_id("CVE-2014-9161");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-05 08:56:43 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-02-03 17:45:52 +0530 (Tue, 03 Feb 2015)");
  script_name("Adobe Reader Out-of-bounds Vulnerability Feb15 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Adobe Reader
  and is prone to unspecified Out-of-bounds error vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The error exists due to an out-of-bounds
  read flaw in CoolType.dll");

  script_tag(name:"impact", value:"Successful exploitation will allow
  context-dependent attacker to cause a crash or potentially disclose memory
  contents.");

  script_tag(name:"affected", value:"Adobe Reader 10.x through 10.1.13 and
  Adobe Reader 11.x through 11.0.10 on on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader 10.1.14 or
  11.0.11 or later.");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/reader/apsb15-10.html");
  script_xref(name:"URL", value:"http://code.google.com/p/google-security-research/issues/detail?id=149");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"10.0", test_version2:"10.1.13"))
{
  fix = "10.1.14";
  VULN = TRUE ;
}


if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.10"))
{
  fix = "11.0.11";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'Installed version: ' + readerVer + '\n' +
           'Fixed version:     ' + fix  + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
