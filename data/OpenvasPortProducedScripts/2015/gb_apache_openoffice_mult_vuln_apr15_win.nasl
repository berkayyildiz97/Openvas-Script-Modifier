###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_openoffice_mult_vuln_apr15_win.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apache OpenOffice Multiple Vulnerabilities Apr15 (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805463");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-3575", "CVE-2014-3524");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-09 13:09:07 +0530 (Thu, 09 Apr 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apache OpenOffice Multiple Vulnerabilities Apr15 (Windows)");

  script_tag(name:"summary", value:"The host is installed with Apache
  OpenOffice and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in application due to the way the it generates OLE previews when
    handling a specially crafted document that is distributed to other parties.

  - An error in application that is triggered when handling specially
    crafted Calc spreadsheets.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to gain access to potentially sensitive information
  and to execute arbitrary commands.");

  script_tag(name:"affected", value:"Apache OpenOffice before 4.1.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache OpenOffice version
  4.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030755");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1030754");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_xref(name:"URL", value:"http://www.openoffice.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!openoffcVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Appache OpenOffice version 4.1.1 is equal to 4.11.9775
if(version_is_less(version:openoffcVer, test_version:"4.11.9775"))
{
  report = 'Installed version: ' + openoffcVer + '\n' +
           'Fixed version:     ' + "4.1.1 (4.11.9775)" + '\n';
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
