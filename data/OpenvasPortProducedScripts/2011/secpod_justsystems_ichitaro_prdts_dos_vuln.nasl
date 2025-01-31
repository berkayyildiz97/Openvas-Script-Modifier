###############################################################################
# OpenVAS Vulnerability Test
#
# JustSystems Ichitaro Products Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902396");
  script_version("2019-12-18T15:04:04+0000");
  script_tag(name:"last_modification", value:"2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_bugtraq_id(48283);
  script_cve_id("CVE-2011-1331");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Products Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ichitaro_or_Viewer/Installed");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN87239473/index.html");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js11001.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000043.html");
  script_xref(name:"URL", value:"http://www.symantec.com/connect/blogs/targeted-attacks-2011-using-ichitaro-zero-day-vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  vulnerable system or cause the application to crash.");

  script_tag(name:"affected", value:"JustSystems Ichitaro version 2005 through 2011

  JustSystems Ichitaro viewer version prior to 20.0.4.0");

  script_tag(name:"insight", value:"The flaw is due to the error while parsing certain documents.");

  script_tag(name:"summary", value:"This host is installed with JustSystems Ichitaro product(s) and is
  prone to denial of service vulnerability.");

  script_tag(name:"solution", value:"Apply the patch for JustSystems Ichitaro or update to JustSystems Ichitaro viewer version 20.0.4.0 or later.");

  script_tag(name:"qod", value:"30"); # nb: Can't detect the Ichitaro Patch level
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

ichitaro_CPE = "cpe:/a:ichitaro:ichitaro";
viewer_CPE = "cpe:/a:justsystem:ichitaro_viewer";

include( "host_details.inc" );
include( "version_func.inc" );

if( version = get_app_version( cpe: ichitaro_CPE, nofork: TRUE ) )
{
  if( version_in_range( version: version, test_version: "2005", test_version2: "2011" ) )
  {
    report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch" );
    if(!port = get_app_port(cpe: viewer_CPE)) port = 0;
    security_message(port:port, data:report);
    exit( 0 );
  }
}

if( version = get_app_version( cpe: viewer_CPE ) )
{
  if( version_is_less( version: version, test_version: "20.0.4.0" ) )
  {
    location = get_app_location( cpe: viewer_CPE );
    report = report_fixed_ver( installed_version: version, fixed_version: "20.0.4.0", install_path: location );
    if(!port = get_app_port(cpe: viewer_CPE)) port = 0;
    security_message(port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );
