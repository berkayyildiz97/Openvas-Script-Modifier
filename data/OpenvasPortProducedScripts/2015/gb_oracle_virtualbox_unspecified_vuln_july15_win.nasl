###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle Virtualbox Unspecified Vulnerability July15 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805723");
  script_version("2019-07-05T09:12:25+0000");
  script_cve_id("CVE-2015-2594");
  script_bugtraq_id(75899);
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-07-21 10:04:16 +0530 (Tue, 21 Jul 2015)");
  script_name("Oracle Virtualbox Unspecified Vulnerability July15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Oracle VM
  virtualBox and is prone to unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 4.0.32,
  4.1.40, 4.2.32, and 4.3.30 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Oracle VirtualBox version
  4.0.32, 4.1.40, 4.2.32, and 4.3.30 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!virtualVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(virtualVer =~ "^(4\.(0|1|2|3))")
{
  if(version_in_range(version:virtualVer, test_version:"4.0.0", test_version2:"4.0.31"))
  {
     fix = "4.0.32";
     VULN = TRUE;
  }
  if(version_in_range(version:virtualVer, test_version:"4.1.0", test_version2:"4.1.39"))
  {
    fix = "4.1.40";
    VULN = TRUE;
  }
  if(version_in_range(version:virtualVer, test_version:"4.2.0", test_version2:"4.2.31"))
  {
    fix = "4.2.32";
    VULN = TRUE;
  }
  if(version_in_range(version:virtualVer, test_version:"4.3.0", test_version2:"4.3.29"))
  {
    fix = "4.3.30";
    VULN = TRUE;
  }
  if(VULN)
  {
    report = 'Installed version: ' + virtualVer + '\n' +
             'Fixed version:     ' + fix + '\n';
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}
