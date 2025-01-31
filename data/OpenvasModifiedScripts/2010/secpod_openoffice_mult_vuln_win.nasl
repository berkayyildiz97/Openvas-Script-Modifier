###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_mult_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# OpenOffice.org Buffer Overflow and Directory Traversal Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902283");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453",
                "CVE-2010-3454", "CVE-2010-4253", "CVE-2010-4643");
  script_bugtraq_id(46031);
  script_name("OpenOffice.org Buffer Overflow and Directory Traversal Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43065");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0230");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0232");
  script_xref(name:"URL", value:"http://www.cs.brown.edu/people/drosenbe/research.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will crash
  the application.");
  script_tag(name:"affected", value:"OpenOffice Version 2.x and 3.x to 3.2.0 on windows.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A buffer overflow error when processing malformed TGA files and PNG files

  - A memory corruption error within the 'WW8ListManager::WW8ListManager()'
    and 'WW8DopTypography::ReadFromMem()' function when processing malformed
    data

  - A memory corruption error when processing malformed RTF data

  - A directory traversal error related to 'zip/jar' package extraction

  - A buffer overflow error when processing malformed PPT files");
  script_tag(name:"solution", value:"Upgrade to OpenOffice Version 3.3.0 or later");
  script_tag(name:"summary", value:"The host has OpenOffice installed and is prone to buffer overflow
  and directory traversal vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openoffice.org/");
  exit(0);
}


include("version_func.inc");

##  Get the version from KB
openVer = get_kb_item("OpenOffice/Win/Ver");

## Exit if script fails to get the version
if(!openVer){
  exit(0);
}

if(openVer =~ "^2.*")
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

if(openVer =~ "^3.*")
{
  ## OpenOffice 3.3 (3.3.9567)
  if(version_is_less(version:openVer, test_version:"3.3.9567")){
    report = report_fixed_ver(installed_version:openVer, fixed_version:"3.3.9567");
    security_message(port: 0, data: report);
  }
}
