module.exports = function(RED) {
    function ThingsboardServerNode(n) {

	    "use strict";
	    var ws = require("ws");
	    var urllib = require("url");

        var request = require('request');
    	var hashSum = require("hash-sum");

        RED.nodes.createNode(this,n);

        this._inputNodes = [];
        this._subscriptions = [];
        this._pendingWsRequests = [];

        this.thingsboardHost = n.thingsboardHost;
        this.mqttPort = n.mqttPort;
        this.wsPort = n.wsPort;
        this.restPort = n.restPort;
        this.username = n.username;
        this.password = n.password;

        this.reqTimeout = 1000;
        this.ret = "obj";

        this.thingsboardBearerToken = ""; // TO FILL AFTER AUTHENTICATION AGAINST THINGSBOARD
        this.thingsboardUser = {}; // TO FILL AFTER AUTHENTICATION AGAINST THINGSBOARD

        var node = this;

        /// msg: typical node-red structure:
        /// msg.payload -> payload of message to be sent
        /// msg.headers -> headers of message to be sent
        /// msg.cookiess -> cookies of message to be sent
        this.requestHttp = function(url, nodeMethod, msg, onResult, isResultPayloadExpected = true) {
        	var preRequestTimestamp = process.hrtime();
            node.status({fill:"blue",shape:"dot",text:"thingsboardserver.status.requesting"});
            //var url = nodeUrl || msg.url;
            //if (msg.url && nodeUrl && (nodeUrl !== msg.url)) {  // revert change below when warning is finally removed
            //    node.warn(RED._("common.errors.nooverride"));
            //}

            RED.log.debug("RequestHttp - url " + url + ", nodeMethod " + nodeMethod + ", msg " + JSON.stringify(msg));

            if (!url) {
                node.error(RED._("thingsboardserver.errors.no-url"),msg);
                return;
            }
            // url must start http:// or https:// so assume http:// if not set
            if (url.indexOf("://") !== -1 && url.indexOf("http") !== 0) {
                node.warn(RED._("thingsboardserver.errors.invalid-transport"));
                node.status({fill:"red",shape:"ring",text:"thingsboardserver.errors.invalid-transport"});
                return;
            }
            if (!((url.indexOf("http://") === 0) || (url.indexOf("https://") === 0))) {
                    url = "http://"+url;
            }

            var method = nodeMethod.toUpperCase() || "GET";

            var opts = urllib.parse(url);
            opts.method = method;
            opts.headers = {};
            var ctSet = "Content-Type"; // set default camel case
            var clSet = "Content-Length";
            if (msg.headers) {
                if (msg.headers.hasOwnProperty('x-node-red-request-node')) {
                    var headerHash = msg.headers['x-node-red-request-node'];
                    delete msg.headers['x-node-red-request-node'];
                    var hash = hashSum(msg.headers);
                    if (hash === headerHash) {
                        delete msg.headers;
                    }
                }
                if (msg.headers) {
                    for (var v in msg.headers) {
                        if (msg.headers.hasOwnProperty(v)) {
                            var name = v.toLowerCase();
                            if (name !== "content-type" && name !== "content-length") {
                                // only normalise the known headers used later in this
                                // function. Otherwise leave them alone.
                                name = v;
                            }
                            else if (name === 'content-type') { ctSet = v; }
                            else { clSet = v; }
                            opts.headers[name] = msg.headers[v];
                        }
                    }
                }
            }
            if (msg.cookies) {
                var cookies = [];
                if (opts.headers.hasOwnProperty('cookie')) {
                    cookies.push(opts.headers.cookie);
                }

                for (var name in msg.cookies) {
                    if (msg.cookies.hasOwnProperty(name)) {
                        if (msg.cookies[name] === null || msg.cookies[name].value === null) {
                            // This case clears a cookie for HTTP In/Response nodes.
                            // Ignore for this node.
                        } else if (typeof msg.cookies[name] === 'object') {
                            cookies.push(cookie.serialize(name,msg.cookies[name].value));
                        } else {
                            cookies.push(cookie.serialize(name,msg.cookies[name]));
                        }
                    }
                }
                if (cookies.length > 0) {
                    opts.headers.cookie = cookies.join("; ");
                }
            }
            var payload = null;

            if (typeof msg.payload !== "undefined" && (method == "POST" || method == "PUT" || method == "PATCH" ) ) {
                if (typeof msg.payload === "string" || Buffer.isBuffer(msg.payload)) {
                    payload = msg.payload;
                } else if (typeof msg.payload == "number") {
                    payload = msg.payload+"";
                } else {
                    if (opts.headers['content-type'] == 'application/x-www-form-urlencoded') {
                        payload = querystring.stringify(msg.payload);
                    } else {
                        payload = JSON.stringify(msg.payload);
                        if (opts.headers['content-type'] == null) {
                            opts.headers[ctSet] = "application/json";
                        }
                    }
                }
                if (opts.headers['content-length'] == null) {
                    if (Buffer.isBuffer(payload)) {
                        opts.headers[clSet] = payload.length;
                    } else {
                        opts.headers[clSet] = Buffer.byteLength(payload);
                    }
                }
            }
            // revert to user supplied Capitalisation if needed.
            if (opts.headers.hasOwnProperty('content-type') && (ctSet !== 'content-type')) {
                opts.headers[ctSet] = opts.headers['content-type'];
                delete opts.headers['content-type'];
            }
            if (opts.headers.hasOwnProperty('content-length') && (clSet !== 'content-length')) {
                opts.headers[clSet] = opts.headers['content-length'];
                delete opts.headers['content-length'];
            }
            var urltotest = url;
            var noproxy;
            var noprox = false;
            if (noprox) {
                for (var i in noprox) {
                    if (url.indexOf(noprox[i]) !== -1) { noproxy=true; }
                }
            }
            var prox = false;
            if (prox && !noproxy) {
                var match = prox.match(/^(http:\/\/)?(.+)?:([0-9]+)?/i);
                if (match) {
                    //opts.protocol = "http:";
                    //opts.host = opts.hostname = match[2];
                    //opts.port = (match[3] != null ? match[3] : 80);
                    opts.headers['Host'] = opts.host;
                    var heads = opts.headers;
                    var path = opts.pathname = opts.href;
                    opts = urllib.parse(prox);
                    opts.path = opts.pathname = path;
                    opts.headers = heads;
                    opts.method = method;
                    urltotest = match[0];
                    if (opts.auth) {
                        opts.headers['Proxy-Authorization'] = "Basic "+new Buffer(opts.auth).toString('Base64')
                    }
                }
                else { node.warn("Bad proxy url: "+process.env.http_proxy); }
            }

            RED.log.debug("RequestHttp - Performing request - url " + url + ", nodeMethod " + nodeMethod + ", msg " + JSON.stringify(msg));

            opts.body = payload;

            request(opts,function(error, res, body) {
                node.status({});
                if (error) {
                  if (error.code === 'ETIMEDOUT') {
                    node.error(RED._("common.notification.errors.no-response"), msg);
                    setTimeout(function () {
                      node.status({
                        fill: "red",
                        shape: "ring",
                        text: "common.notification.errors.no-response"
                      });
                    }, 10);
                  } else {
                    node.error(error, msg);
                    msg.payload = error.toString() + " : " + url;
                    msg.statusCode = error.code;
                    node.send(msg);
                    node.status({
                      fill: "red",
                      shape: "ring",
                      text: error.code
                    });
                  }
                } else {

                    msg.payload = body;

                    try { msg.payload = JSON.parse(msg.payload); } // obj
                    catch(e) { node.warn(RED._("thingsboardserver.errors.json-error")); }

                    RED.log.debug("RequestHttp - Receiving result " + JSON.stringify(msg));
                    onResult(msg);
                }
            });

            RED.log.debug("RequestHttp - Request performed, waiting for response");

            return msg;
        }

        this.setAuthTokenHeader = function(msg) {
			msg.headers = {
			    "X-Authorization" : "Bearer " + this.thingsboardBearerToken
			}
			return msg;
        }

        this.authenticate = function(onResult) {
        	if (!node.isAuthenticated)
        	{
	        	var msg = {
	        		payload: {
					    username: node.username,
					    password: node.password
					}
				};

	        	var res = node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/auth/login", "POST", msg, function(msg) {

		        	RED.log.debug("Authenticate result " + JSON.stringify(res));
		        	node.thingsboardBearerToken = res.payload.token;

		        	// Get user from bearer token
		        	var msg = node.setAuthTokenHeader({});
		        	res = node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/auth/user", "GET", msg, function (msg) {
			        	RED.log.debug("User result " + JSON.stringify(res.payload));
			        	node.thingsboardUser = res.payload;
			        	node.isAuthenticated = res.payload !== undefined;
			        	onResult();
		        	});
	        	});
        	}
        	else
        	{
        		onResult();
        	}
        }

        this.cacheAssets = function() {
        }

        this.startListenWsForAssets = function(assetsToListen) {

        		RED.log.debug("WS - startListenWsForAssets for " + JSON.stringify(assetsToListen));
		    	node.closing = false;
		    	// Store cmd ids
		    	for (var i = 0; i < assetsToListen.length; i++) {
		    		var assetEl = assetsToListen[i];
		    		node._subscriptions[assetEl.cmdId] = assetEl;
		    		/*if (assetEl.tsSubCmds !== undefined)
		    		{
			    		for (var ii = 0; ii < assetEl.tsSubCmds.length; ii++) {
			    			node._subscriptions[assetEl.tsSubCmds[ii].cmdId] = assetEl.tsSubCmds[ii];
			    		}
		    		}
		    		if (assetEl.historyCmds !== undefined)
		    		{
			    		for (var ii = 0; ii < assetEl.tsSubCmds.length; ii++) {
			    			node._subscriptions[assetEl.historyCmds[ii].cmdId] = assetEl.historyCmds[ii];
			    		}
		    		}
		    		if (assetEl.attrSubCmds !== undefined)
		    		{
			    		for (var ii = 0; ii < assetEl.tsSubCmds.length; ii++) {
			    			node._subscriptions[assetEl.attrSubCmds[ii].cmdId] = assetEl.attrSubCmds[ii];
			    		}
		    		}*/
		    	}

		    	startconn(function() {
					var msg = {
						payload : {
			        		tsSubCmds: assetsToListen,
			        		/*
			        		[
				                {
				                entityType: "DEVICE",
				                entityId: "6f347950-c16f-11e7-b08a-f14a0b77c636",  
				                scope: "LATEST_TELEMETRY",
				                cmdId: 10     
				                } 
				            ],
				            */
			            	historyCmds: [],
			            	attrSubCmds: []
			        	}
			    	};


		            var payload;
		            if (msg.hasOwnProperty("payload")) {
		                if (!Buffer.isBuffer(msg.payload)) { // if it's not a buffer make sure it's a string.
		                    payload = RED.util.ensureString(msg.payload);
		                }
		                else {
		                    payload = msg.payload;
		                }
		            }

			    	RED.log.debug("WS - sending to server " + JSON.stringify(msg));

			    	node.server.send(payload);
		    	}); // start outbound connection
        }

        this.getDeviceIdByName = function (deviceName, deviceType, onDeviceResult) {

            node.authenticate(function() {
                 var query = {
                    "deviceTypes": [
                        deviceType
                    ],
                    "parameters": {
                        "rootId": node.thingsboardUser.tenantId.id,
                        "rootType": "TENANT",
                        "direction": "FROM",
                        "maxLevel": 100
                    }
                };

                var msg = {
                    payload: query
                };

                node.setAuthTokenHeader(msg);

                node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/devices", "POST", msg, function(res) {
                    var deviceId;
                    for (var i = 0; i < res.payload.length; i++) {
                        if (res.payload[i].name == deviceName)
                            {
                                deviceId = res.payload[i].id.id;
                            }
                    }

                    onDeviceResult([deviceId]);
                });
            });
        }

        this.getAssetIdByName = function (assetName, assetType, onAssetResult) {

            node.authenticate(function() {
                 var query = {
                    "assetTypes": [
                        assetType
                    ],
                    "parameters": {
                        "rootId": node.thingsboardUser.tenantId.id,
                        "rootType": "TENANT",
                        "direction": "FROM",
                        "maxLevel": 100
                    }
                };

                var msg = {
                    payload: query
                };

                node.setAuthTokenHeader(msg);

                node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/assets", "POST", msg, function(res) {
                    var assetId;
                    for (var i = 0; i < res.payload.length; i++) {
                        if (res.payload[i].name == assetName)
                            {
                                assetId = res.payload[i].id.id;
                            }
                    }

                    onDeviceResult([assetId]);
                });
            });
        }

        this.getDevicesByNamePattern = function (deviceNamePattern, deviceTypes, onDeviceResult) {

            node.authenticate(function() {
                 var query = {
                    "deviceTypes": deviceTypes,
                    "parameters": {
                        "rootId": node.thingsboardUser.tenantId.id,
                        "rootType": "TENANT",
                        "direction": "FROM",
                        "maxLevel": 100
                    }
                };

                var msg = {
                    payload: query
                };

                node.setAuthTokenHeader(msg);

                node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/devices", "POST", msg, function(res) {
                    var re = new RegExp(deviceNamePattern);

                    var devices = [];
                    for (var i = 0; i < res.payload.length; i++) {
                        if (re.test(res.payload[i].name))
                            {
                                devices[devices.length] = {
                                    id:res.payload[i].id.id,
                                    entityType:res.payload[i].id.entityType
                                };
                            }
                    }

                    onDeviceResult(devices);
                });
            });
        }

        this.getAssetsByNamePattern = function (assetNamePattern, assetTypes, onAssetResult) {

            node.authenticate(function() {
                 var query = {
                    "assetTypes": assetTypes,
                    "parameters": {
                        "rootId": node.thingsboardUser.tenantId.id,
                        "rootType": "TENANT",
                        "direction": "FROM",
                        "maxLevel": 100
                    }
                };

                var msg = {
                    payload: query
                };

                RED.log.debug("Getting assets by name pattern " + JSON.stringify(msg));

                node.setAuthTokenHeader(msg);

                node.requestHttp(node.thingsboardHost + ":" + node.restPort + "/api/assets", "POST", msg, function(res) {
                    var re = new RegExp(assetNamePattern);

                    var assets = [];
                    for (var i = 0; i < res.payload.length; i++) {
                        if (re.test(res.payload[i].name))
                            {
                                assets[assets.length] =  {
                                    id:res.payload[i].id.id,
                                    entityType:res.payload[i].id.entityType
                                };
                            }
                    }

                    onAssetResult(assets);
                });
            });
        }

        this.cmdId = 1;
        this.createAssetToListenWs = function (entityId, entityType, scope)
        {
        	/*
			const YEAR = 1000 * 60 * 60 * 24 * 365;
        	        return {
            entityType: datasourceSubscription.entityType,
            entityId: datasourceSubscription.entityId,
            keys: tsKeys,
            startTs: startTs - YEAR,
            endTs: startTs,
            interval: 1000,
            limit: 1,
            agg: types.aggregation.none.value
        };*/
    			/*
    	        var subscriptionCommand = {
                    entityType: datasourceSubscription.entityType,
                    entityId: datasourceSubscription.entityId,
                    keys: tsKeys
                };

                subscriber = {
                    subscriptionCommands: [subscriptionCommand],
                    type: types.dataKeyType.timeseries
                };*/

        		/*
                var attrsSubscriptionCommand = {
                    entityType: datasourceSubscription.entityType,
                    entityId: datasourceSubscription.entityId,
                    keys: attrKeys
                };*/
                this.cmdId++;
        	return {
                entityType: entityType, //"DEVICE",
                entityId: entityId, //"6f347950-c16f-11e7-b08a-f14a0b77c636",  
                scope: scope, //"LATEST_TELEMETRY",
                cmdId: this.cmdId
        	};
        }

        this.disconnectWs = function() {

        }

        this.connectMqtt = function() {

        }
        this.disconnectMqtt = function() {

        }

        function startconn(onOpened) {    // Connect to remote endpoint
            if (onOpened !== undefined)
            {
                node._pendingWsRequests.push({
                    callback:onOpened
                });
            }
        	if (!node.isWsConnected && !node.isWsOpening)
        	{
	            node.tout = null;
	            var path = "ws://" + node.thingsboardHost + ":" + node.wsPort + "/api/ws/plugins/telemetry?token=" + node.thingsboardBearerToken;
	            var socket = new ws(path);
	            socket.setMaxListeners(0);
	            node.server = socket; // keep for closing
	            handleConnection(socket);
        	}
            else if (!node.isWsConnected && node.isOpening)
            {
                // Will be catched by queue
            }
        	else if (!node.isClosing)
        	{
        		if (onOpened !== undefined)
        			onOpened();
        	}
        }

        function handleConnection(/*socket*/socket) {

			RED.log.debug("WS - handling connection for socket " + JSON.stringify(socket));
            var id = (1+Math.random()*4294967295).toString(16);

            socket.on('open',function() {
            	RED.log.debug("WS - opened connection ");
                node.isWsConnected = true;
                node.emit('opened','');

                // Iterate over pending requests
                for (var i = 0; i < node._pendingWsRequests.length; i++) {
                    var callback = node._pendingWsRequests[i];
                    node._pendingWsRequests.splice(i, 1);
                    callback.callback();
                }
            });
            socket.on('close',function() {
                RED.log.debug("WS - closed connection ");
                
                node.isWsConnected = false;

                node.emit('closed');

                if (!node.closing) {
                    clearTimeout(node.tout);
                    node.tout = setTimeout(function() { startconn(); }, 3000); // try to reconnect every 3 secs... bit fast ?
                }
            });
            socket.on('message',function(data,flags) {
            	RED.log.debug("WS - Received message " + data);

                node.handleEvent(id,socket,'message',data,flags);
            });
            socket.on('error', function(err) {
            	RED.log.debug("WS - errored connection with " + err);

                node.emit('erro');
                node.isWsConnected = false;
                if (!node.closing) {
                    clearTimeout(node.tout);
                    node.tout = setTimeout(function() { startconn(); }, 3000); // try to reconnect every 3 secs... bit fast ?
                }
            });
        }

        node.on("close", function() {
            RED.log.debug("WS - closing connection ");
     	    node.closing = true;
            node.server.close();
            if (node.tout) {
                clearTimeout(node.tout);
                node.tout = null;
            }
        });
    }

    ThingsboardServerNode.prototype.registerInputNode = function(/*Node*/handler) {
        this._inputNodes.push(handler);
    }

    ThingsboardServerNode.prototype.removeInputNode = function(/*Node*/handler) {
        this._inputNodes.forEach(function(node, i, inputNodes) {
            if (node === handler) {
                inputNodes.splice(i, 1);
            }
        });
    }

    ThingsboardServerNode.prototype.handleEvent = function(id,/*socket*/socket,/*String*/event,/*Object*/data,/*Object*/flags) {
        var dataParsed = JSON.parse(data);
        var msg = {
            payload:dataParsed
        };
        RED.log.debug("WSClient - HandleEvent for " + JSON.stringify(msg));
        msg._session = {type:"websocket",id:id};

    	// Add subscription device details to msg
    	if (msg.payload !== undefined && msg.payload.subscriptionId !== undefined)
    	{
    		var subs = this._subscriptions[msg.payload.subscriptionId];
    		if (subs !== undefined)
    		{
    			msg.deviceId = subs.entityId;
    		}
            RED.log.debug("HandleEvent - For Subscriptions " + JSON.stringify(this._subscriptions) + "; MSG " + JSON.stringify(msg));
    	}

        for (var i = 0; i < this._inputNodes.length; i++) {
            this._inputNodes[i].send(msg);
        }
    }

    RED.nodes.registerType("thingsboard-server",ThingsboardServerNode);

    function ThingsboardInputNode(n) {
        RED.nodes.createNode(this,n);

        this.deviceNamePattern = n.deviceNamePattern;
        this.isListenToTelemetry = n.isListenToTelemetry;
        this.isListenToAttributes = n.isListenToAttributes;
        this.deviceTypes = n.deviceTypes;

        this.thingsboardServer = n.thingsboardServer;

        this.serverConfig = RED.nodes.getNode(this.thingsboardServer);
        if (this.serverConfig) {
            this.serverConfig.registerInputNode(this);
            // TODO: nls
            this.serverConfig.on('opened', function(n) { node.status({fill:"green",shape:"dot",text:"connected "+n}); });
            this.serverConfig.on('erro', function() { node.status({fill:"red",shape:"ring",text:"error"}); });
            this.serverConfig.on('closed', function() { node.status({fill:"red",shape:"ring",text:"disconnected"}); });
        } else {
            this.error(RED._("thingsboard.errors.missing-conf"));
        }

        var node = this;

        RED.log.debug("InputNode - deviceTypes " + node.deviceTypes + ", deviceNamePattern " + node.deviceNamePattern);

        if (node.deviceTypes !== undefined && node.deviceNamePattern !== undefined)
        {
        	var deviceTypes = node.deviceTypes.split(",").map(function(item) {
			  return item.trim();
			});

	        // Register for messages now by device name and type
	        this.serverConfig.getDevicesByNamePattern(node.deviceNamePattern, deviceTypes, function(devices) {
                // Now also check for assets
                node.serverConfig.getAssetsByNamePattern(node.deviceNamePattern, deviceTypes, function(assets) {
            
                    RED.log.debug("InputNode - read devices " + JSON.stringify(devices) + "; assets " + JSON.stringify(assets));

                    var asset,scope;
                    var assetsParsed = [];
                    var count = 0;
                    for (var i = 0; i < devices.length; i++) {
                        if (node.isListenToTelemetry)
                        {
                            scope = "LATEST_TELEMETRY";
                            asset = node.serverConfig.createAssetToListenWs(devices[i].id, devices[i].entityType, scope);

                            assetsParsed[count] = asset;
                            count++;
                        }
                        if (node.isListenToAttributes)
                        {
                            scope = "LATEST_ATTRIBUTE";
                            asset = node.serverConfig.createAssetToListenWs(devices[i].id, devices[i].entityType, scope);

                            assetsParsed[count] = asset;
                            count++;
                        }
                    }
                    for (var i = 0; i < assets.length; i++) {
                        if (node.isListenToTelemetry)
                        {
                            scope = "LATEST_TELEMETRY";
                            asset = node.serverConfig.createAssetToListenWs(assets[i].id, assets[i].entityType, scope);

                            assetsParsed[count] = asset;
                            count++;
                        }
                        if (node.isListenToAttributes)
                        {
                            scope = "LATEST_ATTRIBUTE";
                            asset = node.serverConfig.createAssetToListenWs(assets[i].id, assets[i].entityType, scope);

                            assetsParsed[count] = asset;
                            count++;
                        }
                    }

                    RED.log.debug("InputNode - Registering for updates for " + JSON.stringify(assetsParsed));

                    if (assetsParsed.length > 0)
                    {
                        node.serverConfig.startListenWsForAssets(
                            assetsParsed, function(msg) {
                                RED.log.debug("LATEST_TELEMETRY received " + JSON.stringify(msg));
                            });
                    }

                    node.on('close', function() {
                        if (node.serverConfig) {
                            node.serverConfig.removeInputNode(node);
                        }
                        node.status({});
                    });
                });
	        });
    	}
    }
    RED.nodes.registerType("thingsboard-input",ThingsboardInputNode);

    function ThingsboardOutputNode(config) {
        RED.nodes.createNode(this,config);

        this.deviceAccessToken = [];
        this.deviceNameIdMapping = [];

        // Requires deviceId and deviceType property in msg object
        this.isDeviceInfoFromMsg = config.isDeviceInfoFromMsg;
        // Overriden if isDeviceInfoFromMsg is set to true
        this.deviceName = config.deviceName;
        this.deviceType = config.deviceType;

        this.thingsboardServer = config.thingsboardServer;

        this.isOutputConfigurationFromMsg = config.isOutputConfigurationFromMsg;
        // Overriden if isOutputConfigurationFromMsg is set to true
        this.isTelemetryUpdate = config.isTelemetryUpdate;
        this.isAttributeUpdate = config.isAttributeUpdate;
        this.isRpcCall = config.isRpcCall;
        this.rpcCallFunction = config.rpcCallFunction;
        this.isRpcTwoWayCall = config.isRpcTwoWayCall;

        this.serverConfig = RED.nodes.getNode(this.thingsboardServer);
        var node = this;
        if (!this.serverConfig) {
            return this.error(RED._("websocket.errors.missing-conf"));
        }


        this.on("input", function(msg) {
        	var isTelemetryUpdate = node.isTelemetryUpdate;
        	var isAttributeUpdate = node.isAttributeUpdate;
        	var isRpcCall = node.isRpcCall;
        	var rpcCallFunction = node.rpcCallFunction;
        	var isRpcTwoWayCall = node.isRpcTwoWayCall;

        	if (node.isOutputConfigurationFromMsg)
        	{
        		isTelemetryUpdate = msg.isTelemetryUpdate;
        		isAttributeUpdate = msg.isAttributeUpdate;
        		isRpcCall = msg.isRpcCall;
        		rpcCallFunction = msg.rpcCallFunction;
        		isRpcTwoWayCall = msg.isRpcTwoWayCall;
        	}

        	RED.log.debug("REST - sending msg " + JSON.stringify(msg));
        	// Now use http api to send device updates
        	/*if (node.deviceAccessToken === undefined)
        	{*/
        	var sendPostData = function(deviceAccessToken, deviceId, msg) {
		       	node.serverConfig.setAuthTokenHeader(msg);

                RED.log.debug("POST result to device " + deviceId + "; MSG " + JSON.stringify(msg));

		       	if (isTelemetryUpdate)
		       	{
			       	node.serverConfig.requestHttp(node.serverConfig.thingsboardHost + ":" + node.serverConfig.restPort + "/api/v1/" + deviceAccessToken + "/telemetry", "POST", msg, function(res) {
				       	RED.log.debug("Publish result " + JSON.stringify(res));
			       	}, false); // No payload in response expected
		       	}
		       	else if (isAttributeUpdate)
		       	{
			       	node.serverConfig.requestHttp(node.serverConfig.thingsboardHost + ":" + node.serverConfig.restPort + "/api/v1/" + deviceAccessToken + "/attributes", "POST", msg, function(res) {
				       	RED.log.debug("Publish result " + JSON.stringify(res));
			       	}, false); // No payload in response expected
		       	}
		       	else if (isRpcCall)
		       	{
		       		//curl -v -X POST -d @set-gpio-request.json http://localhost:8080/api/plugins/rpc/twoway/$DEVICE_ID \
					//--header "Content-Type:application/json" \
					//--header "X-Authorization: $JWT_TOKEN"
					var wayBinding = isRpcTwoWayCall ? "twoway" : "oneway";
			       	node.serverConfig.requestHttp(node.serverConfig.thingsboardHost + ":" + node.serverConfig.restPort + "/api/plugins/rpc/" + wayBinding + "/" + deviceId, "POST", msg, function(res) {
				       	RED.log.debug("RPC call result " + JSON.stringify(res));
			       	}, false); // No payload in response expected
		       	}
			};

    		var subMsg = {};

    		var performAuthedRequest = function(deviceId) {
                var deviceIdStore = deviceId;
                RED.log.debug("Performing authed request for deviceId " + deviceIdStore);
    			if (node.deviceAccessToken[deviceId] === undefined)
    			{
	        		node.serverConfig.setAuthTokenHeader(subMsg);
					node.serverConfig.requestHttp(node.serverConfig.thingsboardHost + ":" + node.serverConfig.restPort + "/api/device/" + deviceIdStore + "/credentials", "GET", subMsg, function(res) {

			        	RED.log.debug("Device accessToken result " + JSON.stringify(res));
			        	node.deviceAccessToken[deviceIdStore] = res.payload.credentialsId;

			        	sendPostData(node.deviceAccessToken[deviceIdStore], deviceIdStore, msg);
		        	});

    			}
    			else
    			{
    				sendPostData(node.deviceAccessToken[deviceIdStore], deviceIdStore, msg);
    			}
    		};

    		if (!node.isDeviceInfoFromMsg)
    		{
    			if (node.deviceNameIdMapping[node.deviceName] !== undefined)
    			{
                    RED.log.debug("Found device name " + node.deviceName + " in dictionary " + JSON.stringify(node.deviceNameIdMapping));
    				performAuthedRequest(node.deviceNameIdMapping[node.deviceName]);
    			}
    			else
    			{
    				node.serverConfig.getDeviceIdByName(node.deviceName, node.deviceType, function(newDeviceId) {
                        if (newDeviceId.length > 0)
                        {
                            node.deviceNameIdMapping[node.deviceName] = newDeviceId[0];
                            performAuthedRequest(newDeviceId[0]);   
                        }  
                        else
                        {    
                            node.serverConfig.getAssetIdByName(node.deviceName, node.deviceType, function(newAssetId) {
                                if (newAssetId.length > 0)
                                {
                                    node.deviceNameIdMapping[node.deviceName] = newAssetId[0];
                                    performAuthedRequest(newAssetId[0]);
                                }
                                else
                                {
                                    RED.log.debug("Not sending anything, because no device found");
                                }
                            });   
                        }
    				});
    			}
    		}
    		else
    		{
    			if (msg.deviceId === undefined)
    			{
                	node.error(RED._("thingsboardserver.errors.no-msg-deviceid"),msg);
    			}
    			else
    			{
    				performAuthedRequest(msg.deviceId);	
    			}
    		}
        	/*}
        	else
        	{
	        	node.serverConfig.setAuthTokenHeader(msg);
	        	node.serverConfig.requestHttp(node.serverConfig.thingsboardHost + ":" + node.serverConfig.restPort + "/api/v1/" + node.deviceAccessToken + "/telemetry", "POST", msg, function(res) {
			        	RED.log.debug("Publish result " + JSON.stringify(res));
		        	});
        	}*/

        });
        this.on('close', function() {
            node.status({});
        });

    }
    RED.nodes.registerType("thingsboard-output",ThingsboardOutputNode);
}