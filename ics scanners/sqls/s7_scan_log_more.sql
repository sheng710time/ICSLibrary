/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50740
Source Host           : localhost:3306
Source Database       : icsdeviceidentifier

Target Server Type    : MYSQL
Target Server Version : 50740
File Encoding         : 65001

Date: 2026-05-13 20:37:37
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for s7_scan_log_more
-- ----------------------------
DROP TABLE IF EXISTS `s7_scan_log_more`;
CREATE TABLE `s7_scan_log_more` (
  `sslm_id` int(12) NOT NULL AUTO_INCREMENT,
  `ip` varchar(64) NOT NULL,
  `port` int(10) NOT NULL,
  `round` int(10) DEFAULT NULL,
  `start_time` datetime DEFAULT NULL,
  `end_time` datetime DEFAULT NULL,
  `response` varchar(255) DEFAULT NULL,
  `scan_way` varchar(255) DEFAULT NULL,
  `vendor` varchar(255) DEFAULT NULL,
  `device_type` varchar(255) DEFAULT NULL,
  `product_code` varchar(255) DEFAULT NULL,
  `product_name` varchar(255) DEFAULT NULL,
  `model_name` varchar(255) DEFAULT NULL,
  `revision` varchar(255) DEFAULT NULL,
  `country` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`sslm_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1023225 DEFAULT CHARSET=utf8;
