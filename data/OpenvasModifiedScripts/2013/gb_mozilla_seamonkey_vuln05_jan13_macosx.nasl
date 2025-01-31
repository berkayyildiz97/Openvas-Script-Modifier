###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_seamonkey_vuln05_jan13_macosx.nasl 11883 2018-10-12 13:31:09Z cfischer $
#
# Mozilla SeaMonkey Multiple Vulnerabilities-05 January13 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.803176");
  script_version("$Revision: 11883 $");
  script_cve_id("CVE-2013-0760", "CVE-2013-0770");
  script_bugtraq_id(57199, 57207);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:31:09 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-16 17:04:59 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla SeaMonkey Multiple Vulnerabilities-05 January13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51752");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027958");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("SeaMonkey/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.");

  script_tag(name:"affected", value:"SeaMonkey version before 2.15 on Mac OS X");

  script_tag(name:"insight", value:"- An error within the 'CharDistributionAnalysis::HandleOneChar()' can be
    exploited to cause a buffer overflow.

  - Unspecified error in the browser engine can be exploited to corrupt memory.");
  script_tag(name:"solution", value:"Upgrade to SeaMonkey version to 2.15 or later.");

  script_tag(name:"summary", value:"This host is installed with Mozilla SeaMonkey and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

seaVer = get_kb_item("SeaMonkey/MacOSX/Version");
if(!seaVer){
  exit(0);
}

if(version_is_less(version:seaVer, test_version:"2.15")){
 report = report_fixed_ver(installed_version:seaVer, fixed_version:"2.15");
 security_message(port: 0, data: report);
}
