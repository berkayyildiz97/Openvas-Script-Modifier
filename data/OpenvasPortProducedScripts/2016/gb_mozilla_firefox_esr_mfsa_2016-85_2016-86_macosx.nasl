###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Esr Security Updates( mfsa_2016-85_2016-86 )-MAC OS X
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809327");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5276", "CVE-2016-5274",
                "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281",
                "CVE-2016-5284", "CVE-2016-5250", "CVE-2016-5261", "CVE-2016-5257");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-09-23 10:26:10 +0530 (Fri, 23 Sep 2016)");
  script_name("Mozilla Firefox Esr Security Updates( mfsa_2016-85_2016-86 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox Esr and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString.

  - Bad cast in nsImageGeometryMixin.

  - Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList.

  - Use-after-free in nsFrameManager::CaptureFrameState.

  - Heap-use-after-free in nsRefreshDriver::Tick.

  - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame.

  - Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap.

  - Use-after-free in DOMSVGLength.

  - Add-on update site certificate pin expiration.

  - Resource Timing API is storing resources sent by the previous page.

  - Integer overflow and memory corruption in WebSocketChannel

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to cause a denial of service, to execute
  arbitrary code, to obtain sensitive full-pathname information.");

  script_tag(name:"affected", value:"Mozilla Firefox Esr version before
  45.4 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox Esr version 45.4
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-86/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"45.4"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"45.4");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
