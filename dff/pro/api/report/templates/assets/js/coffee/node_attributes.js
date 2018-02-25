(function() {
  var Node, Tab,
    __hasProp = Object.prototype.hasOwnProperty,
    __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor; child.__super__ = parent.prototype; return child; };

  namespace("fragments", {
    Node: Node = (function(_super) {

      __extends(Node, _super);

      function Node(json, id) {
        this.json = json;
        this.id = id;
        Node.__super__.constructor.call(this, this.json, this.id);
        this.html = $('<div>');

        this.tablist = null;
        this.table = $('<div>') //.addClass('container');*/
        if (this.json.thumb) this.parseThumb();
        this.parseAttributes();
      }

      Node.prototype.render = function(root) {
      Node.__super__.render.apply(this, arguments);
        this.html.append(this.table);
        return $('nav-tabs#' + this.id + ' a:first').tab('show');
      };

      Node.prototype.parseThumb = function() {
        var link, td, thumb;
        td = $('<td>').attr('width', '10%');
        if (this.json.thumb) {
                link = $('<a>').attr('href', this.json.file);
                thumb = $('<img>').attr('src', this.json.thumb);
                link.append(thumb);
                td.append(link);
        }
        return this.table.append(td);
      };

      Node.prototype.parseAttributes = function() {
        var attr, attrtab, content, counter, item, name, tabcontent, tbody, tr, value, values, _ref;
        if (this.json.row_details['data']) {
          this.tablist = $('<ul>').addClass('nav nav-tabs').attr('id', this.id);
          tabcontent = $('<div>').addClass('tab-content');
          counter = 0;
          _ref = this.json.row_details['data'];
          for (attr in _ref) {
                  values = _ref[attr];
                  item = $('<li>');
                  if (counter === 0) item.addClass('active');
                  item.append($('<a>').attr('data-toggle', 'tab').attr('href', '#' + this.id + attr).append(attr));
                  content = $('<div>').addClass('tab-pane').attr('id', this.id + attr).attr('width', '80%');
                  if (counter === 0) content.addClass('active');
                  attrtab = $('<table>').addClass('table').attr('width', '80%');
                  attrtab.append($('<thead>').append($('<tr>').append($('<th>').append('Attribute')).append($('<th>').append('Values'))));
                  tbody = $('<tbody>');
                  for (name in values) {
                          value = values[name];
                          tr = $('<tr>');
                          tr.append($('<td>').append(name));
                          tr.append($('<td>').append(value));
                          tbody.append(tr);
                  }
                  attrtab.append(tbody);
                  content.append(attrtab);
                  counter++;
                  this.tablist.append(item);
                  tabcontent.append(content);
          }
          this.table.append(this.tablist);
          return this.table.append(tabcontent);
        }
      };

      return Node;

    })(fragments.FObject),
    Tab: Tab = (function(_super) {

      __extends(Tab, _super);

      function Tab(json, id) {
        this.json = json;
        this.id = id;
        Tab.__super__.constructor.call(this, this.json, this.id);
        this.container = $('<div>').addClass('container');
        this.fmanager = new fragments.Manager();
        this.tablist = null;
        this.frags = [];
        this.parseData();
      }

      Tab.prototype.render = function(root) {
        var count, f, _i, _len, _ref, _results;
        Tab.__super__.render.apply(this, arguments);
        this.html.append(this.container);
        $('nav-tabs#' + this.id + ' a:first').tab('show');
        count = 0;
        _ref = this.fmanager.fragments;
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          f = _ref[_i];
          f.render(this.frags[count]);
          _results.push(count++);
        }
        return _results;
      };

      Tab.prototype.parseData = function() {
        var content, counter, frag, fragment, item, tabcontent, td, title, _ref;
        if (this.json.data) {
          td = $('<div>').addClass('container');
          this.tablist = $('<ul>').addClass('nav nav-tabs').attr('id', this.id).attr('width', '80%');
          tabcontent = $('<div>').addClass('tab-content');
          counter = 0;
          _ref = this.json.data;
          for (title in _ref) {
            fragment = _ref[title];
            item = $('<li>');
            if (counter === 0) item.addClass('active');
            item.append($('<a>').attr('data-toggle', 'tab').attr('href', '#' + this.id + title).append(title));
            content = $('<div>').addClass('tab-pane').attr('id', this.id + title).attr('width', '80%');
            if (counter === 0) content.addClass('active');
            frag = this.fmanager.create(fragment);
            this.frags.push(content);
            counter++;
            this.tablist.append(item);
            tabcontent.append(content);
          }
          td.append(this.tablist);
          td.append(tabcontent);
          return this.container.append(td);
        }
      };

      return Tab;

    })(fragments.FObject)
  });

}).call(this);
