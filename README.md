# modnano
Apache module for handling requests via nanomsg XML messages

ModNano is a continuation of the idea of handling web requests via a message queueing library. It is similar in this
way to Mongrel and Mongrel2. ModNano uses nanomsg to avoid licensing issues with ZeroMQ. Unlike Mongrel2, this module
is cross platform compatible. It works on both Windows and Linux/GNU.

This module is meant to be a reference implementation for a full standalone server implementation of the same concept.

Due to the way Apache works, this module blocks each thread while external process is handling a request from the
passed XML. This is suboptimal. As a result this is not meant to be a scalable production method of handling http
requests. Despite that, it will perform well compared to other methods of handling requests in Apache.