###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_solr_dir_trav_vuln_jan14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Apache Solr Directory Traversal Vulnerability Jan-14
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

CPE = "cpe:/a:apache:solr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903508");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-6397");
  script_bugtraq_id(63935);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-29 16:29:04 +0530 (Wed, 29 Jan 2014)");
  script_name("Apache Solr Directory Traversal Vulnerability Jan-14");


  script_tag(name:"summary", value:"This host is installed with Apache Solr and is prone to directory traversal
 vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to improper verification of resource paths passed to certain
Solr REST services within the 'SolrResourceLoader' class.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain potentially
sensitive information.");
  script_tag(name:"affected", value:"Apache Solr before version 4.6");
  script_tag(name:"solution", value:"Upgrade to Apache Solr version 4.6 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55730");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/11/27/1");
  script_xref(name:"URL", value:"http://lucene.apache.org/solr/4_6_0/changes/Changes.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("Apache/Solr/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!solrPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!solrVer = get_app_version(cpe:CPE, port:solrPort)){
  exit(0);
}

if(version_is_less(version:solrVer, test_version:"4.6"))
{
  report = report_fixed_ver(installed_version:solrVer, fixed_version:"4.6");
  security_message(port: solrPort, data: report);
  exit(0);
}
