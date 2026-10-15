/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50740
Source Host           : localhost:3306
Source Database       : icsdeviceidentifier

Target Server Type    : MYSQL
Target Server Version : 50740
File Encoding         : 65001

Date: 2026-05-13 20:37:31
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for s7_scan_info_more
-- ----------------------------
DROP TABLE IF EXISTS `s7_scan_info_more`;
CREATE TABLE `s7_scan_info_more` (
  `ssim_id` int(12) NOT NULL AUTO_INCREMENT,
  `total_ips` int(12) DEFAULT NULL,
  `scanned_ips` int(12) DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `round` int(10) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ssim_id`),
  KEY `index_round` (`round`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=68 DEFAULT CHARSET=utf8;
