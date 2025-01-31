###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Products Updater Service Privilege Escalation Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802867");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2012-1942", "CVE-2012-1943");
  script_bugtraq_id(53803, 53807);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2012-06-19 12:31:59 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products Updater Service Privilege Escalation Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49368");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49366");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-35.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed");
  script_tag(name:"impact", value:"Successful attempt could allow local attackers to bypass security restrictions
  and gain the privileges.");
  script_tag(name:"affected", value:"SeaMonkey version 2.9,
  Thunderbird version 12.0 and
  Mozilla Firefox version 12.0 on Windows");
  script_tag(name:"insight", value:"- Mozilla updater allows to load a local DLL file in a privileged context.

  - The 'Updater.exe' in the Windows Updater Service allows to load an
    arbitrary local wsock32.dll file, which can then be run with the same
    system privileges used by the service.");
  script_tag(name:"summary", value:"This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 13.0 or later, upgrade to SeaMonkey version to 2.10 or later,
  upgrade to Thunderbird version to 13.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mozilla.org/projects/seamonkey/");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/thunderbird/");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  if(version_is_equal(version:ffVer, test_version:"12.0"))
  {
    report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"Equal to 12.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}

seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  if(version_is_equal(version:seaVer, test_version:"2.9"))
  {
    report = report_fixed_ver(installed_version:seaVer, vulnerable_range:"Equal to 2.9");
    security_message(port: 0, data: report);
    exit(0);
  }
}

tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer)
{
  if(version_is_equal(version:tbVer, test_version:"12.0"))
  {
    report = report_fixed_ver(installed_version:tbVer, vulnerable_range:"Equal to 12.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}
