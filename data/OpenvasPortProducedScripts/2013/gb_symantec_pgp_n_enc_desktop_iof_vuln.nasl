###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec PGP Desktop and Encryption Desktop Integer Overflow Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:pgp_desktop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803889");
  script_version("2019-07-05T10:41:31+0000");
  script_cve_id("CVE-2012-4351");
  script_bugtraq_id(57170);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-09-06 17:12:34 +0530 (Fri, 06 Sep 2013)");
  script_name("Symantec PGP Desktop and Encryption Desktop Integer Overflow Vulnerability");


  script_tag(name:"summary", value:"The host is installed with Symantec PGP/Encryption Desktop and is prone to
integer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 10.3.0 MP1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to an unspecified error in pgpwded.sys.");
  script_tag(name:"affected", value:"Symantec PGP Desktop 10.0.x, 10.1.x, and 10.2.x
Symantec Encryption Desktop 10.3.0 prior to 10.3.0 MP1");
  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated attacker to execute
arbitrary code and or gain escalated privileges.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51762");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52219");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_mandatory_keys("PGPDesktop_or_EncryptionDesktop/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!rpVer = get_app_version(cpe:CPE))
{
  CPE = "cpe:/a:symantec:encryption_desktop";
  if(!rpVer = get_app_version(cpe:CPE)){
    exit(0);
  }
}

if(version_in_range(version:rpVer, test_version:"10.0", test_version2:"10.3.0.9059"))
{
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
  exit(0);
}
