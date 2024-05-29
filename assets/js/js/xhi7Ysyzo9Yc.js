if (!AolHelpGlobals) {
	window.AolHelpGlobals = {};
}

AolHelpGlobals.idp.include = (AolHelpGlobals.idp.denylist.indexOf(AolHelpGlobals.brandId) === -1);

jQuery.extend(AolHelpGlobals, {
	isMobile: function() {
		return Modernizr.mq('(max-width: 744px)');
	},
	removeStyles: function(elem) {
		if (!elem) {
			elem = this;
		}
		$(elem).removeAttr('style');
	},
	getCookie: function(name) {
				var start=0,end=0,ck = document.cookie;
				if (ck.length>0) {
						start=ck.indexOf(name + '=');
						if (start!==-1) {
								start = start + name.length+1 ;
								end=ck.indexOf(';',start);
								if (end===-1) {
									end=ck.length;
								}
										return unescape(ck.substring(start,end));
						}
				}
				return '';
		}
	}
);



//----------------------
// AOL Client detection
//----------------------

(function(window, document, $, AH) {

	// Borrowed from the auth plugin
    var isOldAolClient = window.navigator.userAgent.indexOf('aol'),
    	isNewAolClient = typeof window.external !== 'undefined'&& typeof window.external.jsWindow !== 'undefined' && typeof window.external.jsWindow.authState !== 'undefined' ? window.external.jsWindow.authState() : -1;

	AH.isAolClient = isOldAolClient !== -1 || isNewAolClient !== -1;

})(this, document, jQuery, AolHelpGlobals);


//------------------
// Throttling Plugin
//------------------

// Debounce source: http://www.paulirish.com/2009/throttled-smartresize-jquery-event-handler/

(function(window, document, $){

	var sr = 'smartresize',
		ss = 'smartscroll',
		$window = $(window),

		debounce = function (func, threshold, execAsap) {
			var timeout,
				defaultThreshold = 100;

			return function debounced () {
				var obj = this, args = arguments;
				function delayed () {
					if (!execAsap)
						func.apply(obj, args);
					timeout = null;
				}

				if (timeout)
					clearTimeout(timeout);
				else if (execAsap)
					func.apply(obj, args);

				timeout = setTimeout(delayed, threshold || defaultThreshold);
			};
		};

	// Trigger throttled window resize events.
	jQuery.fn[sr] = function(fn) {
		return fn ? this.bind('resize', debounce(fn, 250)) : this.trigger(sr);
	};
	$window[sr](function() {
		$window.trigger('throttledresize');
	});

	// Trigger throttled scroll events.
	jQuery.fn[ss] = function(fn) {
		return fn ? this.bind('scroll', debounce(fn, 50)) : this.trigger(ss);
	};
	$window[ss](function() {
		$window.trigger('throttledscroll');
	});

})(this, document, jQuery);

//------------------------
// CCTS module for Canada 
//------------------------

(function(window, document, $){
	var ccts = document.querySelector('.ccts');

	function toggleExpanded(e) {
		var target = e.target;
		if(target && target.classList.contains('ccts__button')) {
			ccts.classList.toggle('ccts--is-expanded');
		}
	}

	if(ccts) {
		ccts.addEventListener('click', toggleExpanded);
	}

})(this, document, jQuery);

//------------------
// Email Support
//------------------
(function(window, document, $) {
	var $selectEl = $('#hvcSelectDropdow');
	var $emailContainer = $('.hvc-input-container');

	if (!$('#hvcForm').length) {
		return;
	}

	if ($selectEl.length) {
		window.onload = function() {
			// Show email container if select field  equals `access`
			if ($selectEl.val() === 'access') {
				$emailContainer.show();
			}
    	};

		//recheck the email input field display when select input field changes
		$selectEl.on('change', function() {
			if ($(this).val() === "access") {
				return $emailContainer.show();
			}

			$emailContainer.hide();
		});
	}
})(this, document, jQuery)
