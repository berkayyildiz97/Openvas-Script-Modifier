###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_unspecified_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Mozilla Products Multiple Unspecified Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801468");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3175");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Products Multiple Unspecified Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2010/mfsa2010-64.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code.");

  script_tag(name:"affected", value:"Firefox version 3.6.x before 3.6.11

  Thunderbird version 3.1.x before 3.1.5");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified vulnerabilities in the
  browser engine.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox/Thunderbird and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.6.11 or later

  Upgrade to Thunderbird version 3.1.5 or later");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.10"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.6.0 - 3.6.10");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_in_range(version:tbVer, test_version:"3.1.0", test_version2:"3.1.5")){
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"3.1.0 - 3.1.5");
    security_message(port: 0, data: report);
  }
}
