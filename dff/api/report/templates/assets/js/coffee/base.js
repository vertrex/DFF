(function() {
  var Generator;

  this.DFF_DB = {
    databases: {},
    setDatabase: function(name, db) {
      return DFF_DB.databases[name] = db;
    },
    getDatabase: function(name) {
      return DFF_DB.databases[name];
    }
  };

  Generator = (function() {

    function Generator() {
      this.page = new Page();
      this.buildHeader();
      this.refresh(this.firstCategory(), this.firstPage(this.firstCategory()).title);
    }

    Generator.prototype.firstCategory = function() {
      var category, pages;
      for (category in DFF_REPORT_INDEX) {
        pages = DFF_REPORT_INDEX[category];
        return category;
      }
    };

    Generator.prototype.firstPage = function(cname) {
      var category, pages;
      for (category in DFF_REPORT_INDEX) {
        pages = DFF_REPORT_INDEX[category];
        if (category === cname) return pages[0];
      }
    };

    Generator.prototype.getPage = function(cname, pname) {
      var category, page, pages, _i, _len;
      for (category in DFF_REPORT_INDEX) {
        pages = DFF_REPORT_INDEX[category];
        if (category === cname) {
          for (_i = 0, _len = pages.length; _i < _len; _i++) {
            page = pages[_i];
            if (page.title === pname) return page;
          }
        }
      }
    };

    Generator.prototype.buildHeader = function() {
      var category, pages, _results;
      $('ul.nav#categories').empty();
      _results = [];
      for (category in DFF_REPORT_INDEX) {
        pages = DFF_REPORT_INDEX[category];
        _results.push($('ul.nav#categories').append($('<li>').append($('<a>').attr('href', '#').append(category))));
      }
      return _results;
    };

    Generator.prototype.refresh = function(cname, pname) {
      this.refreshNavigation(cname, pname);
      this.page.refresh(this.getPage(cname, pname));
    };

    Generator.prototype.refreshNavigation = function(cname, pname) {
      var category, head, page, page_li, pages, pages_ul, _results;
      $('ul.nav#pages').empty();
      pages_ul = $('ul.nav#pages');
      _results = [];
      for (category in DFF_REPORT_INDEX) {
        pages = DFF_REPORT_INDEX[category];
        head = $('<li>').addClass('nav-header').append(category);
        pages_ul.append(head);
        _results.push((function() {
          var _i, _len, _results2;
          _results2 = [];
          for (_i = 0, _len = pages.length; _i < _len; _i++) {
            page = pages[_i];
            if (page.title === pname && category === cname) {
              page_li = $('<li>').addClass('active');
            } else {
              page_li = $('<li>');
            }
            _results2.push(pages_ul.append(page_li.append($('<a>').attr('href', '#').attr('category', category).append(page.title))));
          }
          return _results2;
        })());
      }
      return _results;
    };

    return Generator;

  })();

  $(function() {
    var gen;
    gen = new Generator;
    $('ul.nav#categories').bind('click', function(event) {
      var cname;
      cname = $(event.target).text();
      if (cname) return gen.refresh(cname, gen.firstPage(cname).title);
    });
    return $('ul.nav#pages').bind('click', function(event) {
      var cname, pname;
      pname = $(event.target).text();
      cname = $(event.target).attr('category');
      if (cname && pname) return gen.refresh(cname, pname);
    });
  });

}).call(this);
