###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_macosx_mult_vuln05_sep14.nasl 14304 2019-03-19 09:10:40Z cfischer $
#
# Apple Mac OS X Multiple Vulnerabilities -05 Sep14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804851");
  script_version("$Revision: 14304 $");
  script_cve_id("CVE-2013-5179", "CVE-2014-1257", "CVE-2014-1260", "CVE-2011-3389");
  script_bugtraq_id(63311, 65777, 49778);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 10:10:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-22 16:50:08 +0530 (Mon, 22 Sep 2014)");

  script_name("Apple Mac OS X Multiple Vulnerabilities -05 Sep14");

  script_tag(name:"summary", value:"This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in the LaunchServices interface within the App Sandbox component.

  - An error when handling session cookies within the CFNetwork.

  - A memory corruption error in handling of Microsoft Office files.

  - A design error exists within the implementation of SSL.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  decrypt data protected by SSL, denial of service attack, arbitrary code
  execution, bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X 10.8.x through 10.8.5");

  script_tag(name:"solution", value:"Run Mac Updates. Please see the references for more information.");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_tag(name:"qod", value:"30"); ## Build information is not available
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.apple.com/kb/HT6150");
  script_xref(name:"URL", value:"http://secunia.com/advisories/55446/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.8\.");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if("Mac OS X" >< osName)
{
  if(version_in_range(version:osVer, test_version:"10.8.0", test_version2:"10.8.5"))
  {
    report = report_fixed_ver(installed_version:osVer, vulnerable_range:"10.8.0 - 10.8.5");
    security_message(port: 0, data: report);
    exit(0);
  }
  exit(99);
}

exit(0);
