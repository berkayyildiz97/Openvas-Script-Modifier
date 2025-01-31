###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox Security Updates( mfsa_2016-85_2016-86 )-Windows
#
# Authors:
# kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809324");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2016-2827", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272",
                "CVE-2016-5273", "CVE-2016-5276", "CVE-2016-5274", "CVE-2016-5277",
                "CVE-2016-5275", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280",
                "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284",
                "CVE-2016-5256", "CVE-2016-5257");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-09-23 10:23:36 +0530 (Fri, 23 Sep 2016)");
  script_name("Mozilla Firefox Security Updates( mfsa_2016-85_2016-86 )-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Out-of-bounds read in mozilla::net::IsValidReferrerPolicy.

  - Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString.

  - Out-of-bounds read in PropertyProvider::GetSpacingInternal.

  - Bad cast in nsImageGeometryMixin.

  - Crash in mozilla::a11y::HyperTextAccessible::GetChildOffset.

  - Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList.

  - Use-after-free in nsFrameManager::CaptureFrameState.

  - Heap-use-after-free in nsRefreshDriver::Tick.

  - Global-buffer-overflow in mozilla::gfx::FilterSupport::ComputeSourceNeededRegions.

  - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame.

  - Full local path of files is available to web pages after drag and drop.

  - Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap.

  - Use-after-free in DOMSVGLength.

  - Favicons can be loaded through non-whitelisted protocols.

  - 'iframe src' fragment timing attack can reveal cross-origin data.

  - Add-on update site certificate pin expiration.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities remote attackers to cause a denial of service, to execute
  arbitrary code, to obtain sensitive full-pathname information.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  49 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 49
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_less(version:ffVer, test_version:"49"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"49");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
