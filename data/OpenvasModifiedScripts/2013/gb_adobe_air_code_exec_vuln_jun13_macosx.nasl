###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_code_exec_vuln_jun13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Adobe Air Remote Code Execution Vulnerability -June13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803665");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-3343");
  script_bugtraq_id(60478);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-18 15:37:02 +0530 (Tue, 18 Jun 2013)");
  script_name("Adobe Air Remote Code Execution Vulnerability -June13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53751");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Air 3.7.0.1860 and earlier on Mac OS X");
  script_tag(name:"insight", value:"Unspecified flaw due to improper sanitization of user-supplied input.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.7.0.2100 or later.");
  script_tag(name:"summary", value:"This host is installed with Adobe Air and is prone to remote code
  execution vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://get.adobe.com/air");
  exit(0);
}

include("version_func.inc");

airVer = get_kb_item("Adobe/Air/MacOSX/Version");
if(airVer)
{
  if(version_is_less_equal(version:airVer, test_version:"3.7.0.1860"))
  {
    report = report_fixed_ver(installed_version:airVer, vulnerable_range:"Less than or equal to 3.7.0.1860");
    security_message(port: 0, data: report);
    exit(0);
  }
}
