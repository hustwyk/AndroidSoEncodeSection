# AndroidSoEncodeSection

结合了四哥的[《Android逆向之旅---Android应用的汉化功能(修改SO中的字符串内容)》](http://www.520monkey.com/archives/561)和[《Android逆向之旅---基于对so中的section加密技术实现so加固》](http://www.520monkey.com/archives/565)的encode方法，为了解决android7.0之后对so库section header校验导致的无处放置new section offset和new section size的问题。

PS：图文说明请见[《Android so库加密Section 内存解密》](https://hollybee.wang/post/androidencodesection/)。
