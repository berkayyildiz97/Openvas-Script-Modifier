###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln01_nov13_win.nasl 31965 2013-11-07 11:59:47Z nov$
#
# Mozilla Firefox Multiple Vulnerabilities-01 Nov13 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804130");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2013-5603", "CVE-2013-5604", "CVE-2013-5602", "CVE-2013-5601",
                "CVE-2013-5600", "CVE-2013-5599", "CVE-2013-5598", "CVE-2013-5597",
                "CVE-2013-5591", "CVE-2013-5590", "CVE-2013-5592", "CVE-2013-5593",
                "CVE-2013-5595", "CVE-2013-5596");
  script_bugtraq_id(63416, 63430, 63424, 63428, 63427, 63423, 63419, 63422,
                    63417, 63415, 63418, 63429, 63421, 63420);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2013-11-07 11:28:51 +0530 (Thu, 07 Nov 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-01 Nov13 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 25.0 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Use-after-free vulnerability in the
'nsContentUtils::ContentIsHostIncludingDescendantOf' function.

  - Improper data initialization in the 'txXPathNodeUtils::getBaseURI' function.

  - An error in 'Worker::SetEventListener' function in the Web workers
implementation.

  - Use-after-free vulnerability in the
'nsEventListenerManager::SetEventHandler' function.

  - Use-after-free vulnerability in 'nsIOService::NewChannelFromURIWithProxyFlags'
function.

  - Use-after-free vulnerability in the 'nsIPresShell::GetPresContext' function.

  - Improper handling of the appending of an IFRAME element in 'PDF.js'.

  - Use-after-free vulnerability in 'nsDocLoader::doStopDocumentLoad' function.

  - Multiple unspecified vulnerabilities in the browser engine.

  - Improper restriction of the nature or placement of HTML within a dropdown
menu.

  - Improper memory allocation for unspecified functions by JavaScript engine.

  - Improper determination of the thread for release of an image object.");
  script_tag(name:"affected", value:"Mozilla Firefox before version 25.0 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service, spoof the address bar, conduct clickjacking attacks
and conduct buffer overflow attacks.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55520");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-102.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:ffVer, test_version:"25.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"25.0");
  security_message(data:report);
  exit(0);
}
